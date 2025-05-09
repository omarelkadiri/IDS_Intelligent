#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Ce script convertit les fichiers de logs Zeek en format compatible avec le dataset NSL-KDD
pour entraîner un système de détection d'intrusion (IDS) intelligent.
"""

import os
import gzip
import json
import csv
import re
import ipaddress
from datetime import datetime
from collections import defaultdict

class ZeekToNSLKDD:
    def __init__(self, zeek_logs_dir, output_file="nslkdd_format.csv"):
        """
        Initialise le convertisseur Zeek vers NSL-KDD.
        
        Args:
            zeek_logs_dir (str): Chemin vers le répertoire contenant les logs Zeek
            output_file (str): Nom du fichier de sortie au format NSL-KDD
        """
        self.zeek_logs_dir = zeek_logs_dir
        self.output_file = output_file
        
        # Dictionnaire pour stocker les données extraites des différents logs
        self.connections = {}
        
        # Mappage des services Zeek vers les services NSL-KDD
        self.service_mapping = {
            'dns': 'domain',
            'http': 'http',
            'https': 'http_443',
            'ssh': 'ssh',
            'ftp': 'ftp',
            'ftp-data': 'ftp_data',
            'smtp': 'smtp',
            'pop3': 'pop_3',
            'imap': 'imap4',
            'telnet': 'telnet',
            'nntp': 'nntp',
            'irc': 'IRC',
            'whois': 'whois',
            'ssl': 'private',  # Approximation
            'dhcp': 'other',
            'ntp': 'ntp_u',
            'ldap': 'ldap',
            'finger': 'finger',
            # Compléter avec d'autres mappages selon besoin
            # Par défaut, 'other' sera utilisé
        }
        
        # Mappage des flags de connexion TCP entre Zeek et NSL-KDD
        self.flag_mapping = {
            'S0': 'S0',       # Connection attempt seen, no reply
            'SF': 'SF',       # Normal establishment and termination
            'REJ': 'REJ',     # Connection attempt rejected
            'S1': 'S1',       # Connection established, not terminated
            'S2': 'S2',       # Connection established and close attempt by originator seen
            'S3': 'S3',       # Connection established and close attempt by responder seen
            'RSTO': 'RSTO',   # Connection established, originator aborted
            'RSTR': 'RSTR',   # Established, responder aborted
            'RSTOS0': 'RSTOS0', # Originator sent a SYN followed by a RST
            'SH': 'SH',       # Originator sent a SYN followed by a FIN
            'OTH': 'OTH',     # No SYN, not closed
        }
        
        # Attributs NSL-KDD que nous allons remplir
        self.nslkdd_attributes = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 
            'wrong_fragment', 'hot', 'logged_in', 'num_compromised', 'count', 
            'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate'
        ]

    def read_log_file(self, file_path):
        """
        Lit un fichier de log Zeek (gzippé ou non) et retourne les enregistrements sous forme de liste de dictionnaires.
        
        Args:
            file_path (str): Chemin vers le fichier de log Zeek
            
        Returns:
            list: Liste de dictionnaires représentant les enregistrements du fichier log
        """
        records = []
        
        # Vérifier si le fichier est gzippé
        if file_path.endswith('.gz'):
            open_func = gzip.open
        else:
            open_func = open
        
        try:
            with open_func(file_path, 'rt', encoding='utf-8') as f:
                # Ignorer les lignes de commentaire et l'en-tête
                header = None
                types = None
                for line in f:
                    line = line.strip()
                    if line.startswith('#'):
                        if line.startswith('#fields'):
                            header = line[8:].strip().split('\t')
                        elif line.startswith('#types'):
                            types = line[7:].strip().split('\t')
                        continue
                    
                    if header:
                        values = line.split('\t')
                        record = {}
                        for i, field in enumerate(header):
                            if i < len(values):
                                # Gérer les valeurs manquantes (représentées par '-' dans Zeek)
                                if values[i] == '-':
                                    record[field] = None
                                else:
                                    record[field] = values[i]
                            else:
                                record[field] = None
                        records.append(record)
        except Exception as e:
            print(f"Erreur lors de la lecture du fichier {file_path}: {e}")
        
        return records

    def extract_connection_data(self):
        """
        Extrait les données de connexion pertinentes à partir des fichiers de logs Zeek.
        """
        # Parcourir tous les fichiers de logs dans le répertoire
        for date_dir in os.listdir(self.zeek_logs_dir):
            date_path = os.path.join(self.zeek_logs_dir, date_dir)
            if not os.path.isdir(date_path):
                continue
                
            # Traiter les fichiers conn.log
            conn_logs = [f for f in os.listdir(date_path) if f.startswith('conn.') and f.endswith('.log.gz')]
            for conn_log in conn_logs:
                conn_records = self.read_log_file(os.path.join(date_path, conn_log))
                
                for record in conn_records:
                    if not record or 'uid' not in record:
                        continue
                        
                    uid = record['uid']
                    self.connections[uid] = {
                        'ts': record.get('ts'),
                        'uid': uid,
                        'id.orig_h': record.get('id.orig_h'),
                        'id.orig_p': record.get('id.orig_p'),
                        'id.resp_h': record.get('id.resp_h'),
                        'id.resp_p': record.get('id.resp_p'),
                        'proto': record.get('proto'),
                        'service': record.get('service'),
                        'duration': record.get('duration'),
                        'orig_bytes': record.get('orig_bytes'),
                        'resp_bytes': record.get('resp_bytes'),
                        'conn_state': record.get('conn_state'),
                        'missed_bytes': record.get('missed_bytes'),
                        'history': record.get('history'),
                        'orig_pkts': record.get('orig_pkts'),
                        'orig_ip_bytes': record.get('orig_ip_bytes'),
                        'resp_pkts': record.get('resp_pkts'),
                        'resp_ip_bytes': record.get('resp_ip_bytes')
                    }
            
            # Enrichir avec les données des autres logs (HTTP, DNS, SSL, etc.)
            self.enrich_with_protocol_logs(date_path)
            
    def enrich_with_protocol_logs(self, date_path):
        """
        Enrichit les données de connexion avec les informations des logs spécifiques aux protocoles.
        
        Args:
            date_path (str): Chemin vers le répertoire contenant les logs d'une date spécifique
        """
        # Liste des logs de protocole à traiter
        protocol_logs = {
            'http': 'http.',
            'dns': 'dns.',
            'ssh': 'ssh.',
            'ssl': 'ssl.',
            'ftp': 'ftp.',
            'smtp': 'smtp.',
            'dhcp': 'dhcp.',
            'ntp': 'ntp.',
            'weird': 'weird.'
        }
        
        for protocol, prefix in protocol_logs.items():
            log_files = [f for f in os.listdir(date_path) if f.startswith(prefix) and f.endswith('.log.gz')]
            
            for log_file in log_files:
                records = self.read_log_file(os.path.join(date_path, log_file))
                
                for record in records:
                    if not record or 'uid' not in record:
                        continue
                        
                    uid = record['uid']
                    if uid in self.connections:
                        # Si la connexion existe déjà, enrichir avec les données spécifiques au protocole
                        if protocol not in self.connections[uid]:
                            self.connections[uid][protocol] = []
                        self.connections[uid][protocol].append(record)
                        
                        # Si le service n'est pas défini dans les données de connexion, le définir
                        if not self.connections[uid]['service']:
                            self.connections[uid]['service'] = protocol

    def compute_nslkdd_features(self):
        """
        Calcule les caractéristiques au format NSL-KDD à partir des données de connexion.
        
        Returns:
            list: Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        nslkdd_records = []
        
        # Dictionnaires pour le calcul des caractéristiques basées sur le temps
        host_connections = defaultdict(list)  # Pour les connexions par host
        srv_connections = defaultdict(list)   # Pour les connexions par service
        
        # Trier les connexions par timestamp
        sorted_connections = sorted(self.connections.values(), key=lambda x: float(x['ts']) if x['ts'] else 0)
        
        for conn in sorted_connections:
            # Extraire les caractéristiques de base
            nslkdd_record = {}
            
            # 1. duration: durée de la connexion en secondes
            nslkdd_record['duration'] = conn['duration'] if conn['duration'] else 0
            
            # 2. protocol_type: type de protocole (tcp, udp, icmp)
            proto = conn['proto'].lower() if conn['proto'] else 'tcp'
            if proto not in ['tcp', 'udp', 'icmp']:
                proto = 'tcp'  # Valeur par défaut
            nslkdd_record['protocol_type'] = proto
            
            # 3. service: type de service de destination
            service = conn['service'] if conn['service'] else 'other'
            nslkdd_record['service'] = self.service_mapping.get(service, 'other')
            
            # 4. flag: état de la connexion
            # Mapper l'état de connexion Zeek vers NSL-KDD
            conn_state = conn['conn_state'] if conn['conn_state'] else 'OTH'
            nslkdd_record['flag'] = self.flag_mapping.get(conn_state, 'OTH')
            
            # 5. src_bytes: nombre d'octets de la source vers la destination
            nslkdd_record['src_bytes'] = int(conn['orig_bytes']) if conn['orig_bytes'] else 0
            
            # 6. dst_bytes: nombre d'octets de la destination vers la source
            nslkdd_record['dst_bytes'] = int(conn['resp_bytes']) if conn['resp_bytes'] else 0
            
            # 7. wrong_fragment: nombre de fragments "erronés"
            # Cette information n'est pas directement disponible dans Zeek
            nslkdd_record['wrong_fragment'] = self.compute_wrong_fragment(conn)
            
            # 8. hot: nombre d'indicateurs "hot"
            # Cette information n'est pas directement disponible dans Zeek
            nslkdd_record['hot'] = self.compute_hot_indicators(conn)
            
            # 9. logged_in: connexion réussie (1) ou non (0)
            nslkdd_record['logged_in'] = self.compute_logged_in(conn)
            
            # 10. num_compromised: nombre d'actions "compromised"
            # Cette information n'est pas directement disponible dans Zeek
            nslkdd_record['num_compromised'] = self.compute_num_compromised(conn)
            
            # Caractéristiques basées sur le temps (window-based)
            # Mettre à jour les listes de connexions pour le calcul des statistiques
            src_ip = conn['id.orig_h']
            if src_ip:
                host_connections[src_ip].append(conn)
            
            # 11. count: nombre de connexions vers la même destination dans les 2 dernières secondes
            nslkdd_record['count'] = self.compute_same_host_count(conn, host_connections)
            
            # 12. srv_count: nombre de connexions vers le même service dans les 2 dernières secondes
            nslkdd_record['srv_count'] = self.compute_same_service_count(conn, srv_connections)
            
            # 13, 14, 15. Taux d'erreurs (serror_rate, srv_serror_rate, rerror_rate)
            error_rates = self.compute_error_rates(conn, host_connections, srv_connections)
            nslkdd_record['serror_rate'] = error_rates['serror_rate']
            nslkdd_record['srv_serror_rate'] = error_rates['srv_serror_rate']
            nslkdd_record['rerror_rate'] = error_rates['rerror_rate']
            
            nslkdd_records.append(nslkdd_record)
        
        return nslkdd_records

    def compute_wrong_fragment(self, conn):
        """
        Fonction d'espace réservé pour calculer le nombre de fragments erronés.
        Cette information n'est pas directement disponible dans Zeek.
        
        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            int: Nombre estimé de fragments erronés
        """
        # Cette caractéristique pourrait être estimée à partir des logs 'weird'
        # Pour l'instant, retournons une valeur par défaut
        if 'weird' in conn and conn['weird']:
            # Compter les événements weird liés à des problèmes de fragmentation
            frag_issues = sum(1 for weird in conn['weird'] 
                              if weird.get('name') and 'frag' in weird['name'].lower())
            return frag_issues
        return 0

    def compute_hot_indicators(self, conn):
        """
        Fonction d'espace réservé pour calculer le nombre d'indicateurs "hot".
        Cette caractéristique fait référence à des indicateurs de compromission
        ou d'activités potentiellement malveillantes.
        
        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            int: Nombre estimé d'indicateurs "hot"
        """
        # Pour un IDS complet, cette fonction devrait analyser les logs
        # à la recherche d'indicateurs de compromission
        hot_count = 0
        
        # Exemple: vérifier si des commandes de système sont présentes dans les URL HTTP
        if 'http' in conn and conn['http']:
            for http_req in conn['http']:
                uri = http_req.get('uri', '')
                if uri:
                    # Recherche de motifs suspects dans les URI
                    suspicious_patterns = ['cmd=', 'exec=', '/bin/', '/etc/', 'passwd', 
                                          'shadow', '.php?', 'eval(', 'system(']
                    hot_count += sum(1 for pattern in suspicious_patterns if pattern in uri)
        
        return hot_count

    def compute_logged_in(self, conn):
        """
        Détermine si une connexion représente une session authentifiée.
        
        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            str: '1' si authentifié, '0' sinon
        """
        # Vérifier les services qui nécessitent généralement une authentification
        auth_services = ['ssh', 'ftp', 'smtp', 'pop3', 'imap', 'telnet']
        service = conn['service']
        
        # Si c'est un service authentifié et la connexion est établie (SF)
        if service in auth_services and conn['conn_state'] == 'SF':
            # Vérifier les logs spécifiques pour confirmer l'authentification
            if service == 'ssh' and 'ssh' in conn:
                for ssh_log in conn['ssh']:
                    if ssh_log.get('auth_success') == 'true':
                        return '1'
            elif service == 'ftp' and 'ftp' in conn:
                for ftp_log in conn['ftp']:
                    if ftp_log.get('user') and ftp_log.get('password'):
                        return '1'
            # Par défaut pour les services authentifiés avec une connexion établie
            return '1'
        
        # HTTP peut avoir des authentifications
        if 'http' in conn and conn['http']:
            for http_req in conn['http']:
                if http_req.get('username') or 'Authorization' in (http_req.get('request_headers', '') or ''):
                    return '1'
        
        return '0'

    def compute_num_compromised(self, conn):
        """
        Fonction d'espace réservé pour estimer le nombre d'actions "compromised".
        
        Args:
            conn (dict): Données de connexion Zeek
            
        Returns:
            int: Nombre estimé d'actions "compromised"
        """
        # Cette fonction devrait idéalement analyser les logs à la recherche
        # d'indicateurs de compromission spécifiques
        compromised_count = 0
        
        # Exemple: vérifier les notices de sécurité
        if 'notice' in conn and conn['notice']:
            for notice in conn['notice']:
                notice_type = notice.get('note', '')
                if any(x in notice_type.lower() for x in ['exploit', 'attack', 'backdoor', 'trojan']):
                    compromised_count += 1
        
        return compromised_count

    def compute_same_host_count(self, conn, host_connections):
        """
        Calcule le nombre de connexions vers la même destination dans les 2 dernières secondes.
        
        Args:
            conn (dict): Données de connexion actuelle
            host_connections (dict): Dictionnaire des connexions par hôte source
            
        Returns:
            int: Nombre de connexions vers la même destination
        """
        if not conn['ts'] or not conn['id.resp_h']:
            return 0
            
        current_ts = float(conn['ts'])
        dest_ip = conn['id.resp_h']
        
        # Compter les connexions vers la même destination dans une fenêtre de 2 secondes
        count = sum(1 for c in host_connections.get(conn['id.orig_h'], [])
                   if c['id.resp_h'] == dest_ip and 
                   float(c['ts']) >= current_ts - 2 and 
                   float(c['ts']) <= current_ts)
        
        return count

    def compute_same_service_count(self, conn, srv_connections):
        """
        Calcule le nombre de connexions vers le même service dans les 2 dernières secondes.
        
        Args:
            conn (dict): Données de connexion actuelle
            srv_connections (dict): Dictionnaire des connexions par service
            
        Returns:
            int: Nombre de connexions vers le même service
        """
        if not conn['ts'] or not conn['service']:
            return 0
            
        current_ts = float(conn['ts'])
        service = conn['service']
        
        # Mettre à jour le dictionnaire des services
        if service not in srv_connections:
            srv_connections[service] = []
        srv_connections[service].append(conn)
        
        # Compter les connexions vers le même service dans une fenêtre de 2 secondes
        count = sum(1 for c in srv_connections[service]
                   if float(c['ts']) >= current_ts - 2 and 
                   float(c['ts']) <= current_ts)
        
        return count

    def compute_error_rates(self, conn, host_connections, srv_connections):
        """
        Calcule les taux d'erreurs pour différentes catégories.
        
        Args:
            conn (dict): Données de connexion actuelle
            host_connections (dict): Dictionnaire des connexions par hôte source
            srv_connections (dict): Dictionnaire des connexions par service
            
        Returns:
            dict: Dictionnaire contenant les différents taux d'erreurs
        """
        error_rates = {
            'serror_rate': 0.0,      # Taux de connexions SYN error vers la même dest
            'srv_serror_rate': 0.0,  # Taux de connexions SYN error vers le même service
            'rerror_rate': 0.0       # Taux de connexions REJ error vers la même dest
        }
        
        if not conn['ts'] or not conn['id.orig_h']:
            return error_rates
            
        current_ts = float(conn['ts'])
        src_ip = conn['id.orig_h']
        dest_ip = conn['id.resp_h']
        service = conn['service']
        
        # Connexions récentes vers la même destination
        same_host_conns = [c for c in host_connections.get(src_ip, [])
                         if c['id.resp_h'] == dest_ip and 
                         float(c['ts']) >= current_ts - 2 and 
                         float(c['ts']) <= current_ts]
        
        # Connexions récentes vers le même service
        same_srv_conns = [c for c in srv_connections.get(service, [])
                        if float(c['ts']) >= current_ts - 2 and 
                         float(c['ts']) <= current_ts]
        
        # Calculer les taux d'erreurs
        if same_host_conns:
            error_rates['serror_rate'] = sum(1 for c in same_host_conns 
                                         if c['conn_state'] == 'S0') / len(same_host_conns)
            error_rates['rerror_rate'] = sum(1 for c in same_host_conns 
                                         if c['conn_state'] == 'REJ') / len(same_host_conns)
                                         
        if same_srv_conns:
            error_rates['srv_serror_rate'] = sum(1 for c in same_srv_conns 
                                              if c['conn_state'] == 'S0') / len(same_srv_conns)
        
        return error_rates

    def write_nslkdd_format(self, nslkdd_records):
        """
        Écrit les enregistrements au format NSL-KDD dans un fichier CSV.
        
        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.nslkdd_attributes)
            writer.writeheader()
            for record in nslkdd_records:
                writer.writerow(record)
                
        print(f"Fichier de sortie '{self.output_file}' créé avec succès!")
        print(f"Nombre d'enregistrements: {len(nslkdd_records)}")

    def convert(self):
        """
        Exécute le processus complet de conversion des logs Zeek vers le format NSL-KDD.
        """
        print("Début de la conversion des logs Zeek vers le format NSL-KDD...")
        print(f"Répertoire des logs Zeek: {self.zeek_logs_dir}")
        print(f"Fichier de sortie: {self.output_file}")
        
        # 1. Extraire les données de connexion
        print("Extraction des données de connexion...")
        self.extract_connection_data()
        print(f"Nombre de connexions extraites: {len(self.connections)}")
        
        # 2. Calculer les caractéristiques NSL-KDD
        print("Calcul des caractéristiques NSL-KDD...")
        nslkdd_records = self.compute_nslkdd_features()
        
        # 3. Écrire le fichier de sortie
        print("Écriture du fichier de sortie...")
        self.write_nslkdd_format(nslkdd_records)
        
        print("Conversion terminée avec succès!")

# Exemple d'utilisation
if __name__ == "__main__":
    # Chemin vers le répertoire contenant les logs Zeek
    zeek_logs_dir = "/opt/zeek/logs"
    
    # Nom du fichier de sortie
    output_file = "nslkdd_format.csv"
    
    # Créer le convertisseur et exécuter la conversion
    converter = ZeekToNSLKDD(zeek_logs_dir, output_file)
    converter.convert()