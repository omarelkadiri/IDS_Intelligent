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
    def __init__(self, zeek_logs_dir, output_file="nslkdd_format.csv", real_time=False, es_integration=False):
        """
        Initialise le convertisseur Zeek vers NSL-KDD avec des options supplémentaires.

        Args:
            zeek_logs_dir (str): Chemin vers le répertoire contenant les logs Zeek
            output_file (str): Nom du fichier de sortie au format NSL-KDD
            real_time (bool): Si True, surveille les logs en temps réel
            es_integration (bool): Si True, intègre les données dans ElasticSearch
        """
        self.zeek_logs_dir = zeek_logs_dir
        self.output_file = output_file
        self.real_time = real_time
        self.es_integration = es_integration
        self.real_time_logs_dir = "/opt/zeek/spool/zeek"  # Répertoire des logs en temps réel

        # Configuration ElasticSearch
        self.es_config = {
            "url": "https://elasticsearch.service:9200",
            "api_key": "ZUdDc1VKUUJXUEhKR0N5eXF1Rng6c1NTOU4xN29SZXFWMHA4eDhRWnNjdw==",
            "index": "zeek-ids-analytics",
            "batch_size": 1000  # Nombre max de documents à envoyer en un seul appel bulk
        }

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

    def is_new_file(self, file_path):
        """Vérifie si un fichier n'a pas encore été traité"""
        return file_path not in self.processed_files

    def mark_file_as_processed(self, file_path):
        """Marque un fichier comme déjà traité"""
        self.processed_files.add(file_path)

    def extract_connection_data(self, real_time=False):
        """
        Extrait les données de connexion pertinentes à partir des fichiers de logs Zeek.

        Args:
            real_time (bool): Si True, ne traite que les nouveaux fichiers depuis le dernier traitement
        """
        # Initialiser conn_records pour éviter UnboundLocalError
        conn_records = []

        # Parcourir tous les fichiers de logs dans le répertoire
        for date_dir in os.listdir(self.zeek_logs_dir):
            date_path = os.path.join(self.zeek_logs_dir, date_dir)
            if not os.path.isdir(date_path):
                continue

            # Traiter les fichiers conn.log
            conn_logs = [f for f in os.listdir(date_path) if f.startswith('conn.') and f.endswith('.log.gz')]

            # En mode temps réel, ne traiter que les nouveaux fichiers
            if real_time:
                conn_logs = [f for f in conn_logs if self.is_new_file(os.path.join(date_path, f))]
                if not conn_logs:  # Aucun nouveau fichier à traiter
                    continue

            for conn_log in conn_logs:
                try:
                    current_records = self.read_log_file(os.path.join(date_path, conn_log))
                    if current_records:
                        conn_records.extend(current_records)
                        # Marquer le fichier comme traité pour le mode temps réel
                        if real_time:
                            self.mark_file_as_processed(os.path.join(date_path, conn_log))
                except Exception as e:
                    print(f"Erreur lors de la lecture du fichier {conn_log}: {str(e)}")
                    continue

            # Traitement des enregistrements
            new_connections = 0
            for record in conn_records:
                if not record or 'uid' not in record:
                    continue

                uid = record['uid']
                # Ne traiter que les nouvelles connexions non déjà enregistrées
                if uid not in self.connections:
                    ts = record.get('ts')
                    # Valider le timestamp
                    if not ts or '\x00' in ts or not ts.replace('.', '').replace('-', '').isdigit():
                        print(f"Skipping invalid timestamp '{ts}' for connection {uid}")
                        continue

                    self.connections[uid] = {
                        'ts': ts,
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
                    new_connections += 1

            # Enrichir avec les données des autres logs (HTTP, DNS, SSL, etc.)
            self.enrich_with_protocol_logs(date_path, real_time)

            return new_connections
            
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

        # Trier les connexions par timestamp, en gérant les timestamps invalides
        def get_timestamp(conn):
            ts = conn.get('ts')
            if ts and isinstance(ts, str):
                try:
                    return float(ts)
                except ValueError:
                    print(f"Warning: Invalid timestamp '{ts}' for connection {conn.get('uid', 'unknown')}. Using 0.")
                    return 0
            return 0

        sorted_connections = sorted(self.connections.values(), key=get_timestamp)

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
        if not conn.get('ts') or not conn.get('id.resp_h'):
            return 0

        def get_timestamp(c):
            ts = c.get('ts')
            if ts and isinstance(ts, str):
                try:
                    return float(ts)
                except ValueError:
                    print(f"Warning: Invalid timestamp '{ts}' for connection {c.get('uid', 'unknown')}. Using 0.")
                    return 0
            return 0

        current_ts = get_timestamp(conn)
        dest_ip = conn['id.resp_h']

        # Compter les connexions vers la même destination dans une fenêtre de 2 secondes
        count = sum(1 for c in host_connections.get(conn['id.orig_h'], [])
                    if c['id.resp_h'] == dest_ip and
                    get_timestamp(c) >= current_ts - 2 and
                    get_timestamp(c) <= current_ts)

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

        if not conn.get('ts') or not conn.get('id.orig_h'):
            return error_rates

        def get_timestamp(c):
            ts = c.get('ts')
            if ts and isinstance(ts, str):
                try:
                    return float(ts)
                except ValueError:
                    print(f"Warning: Invalid timestamp '{ts}' for connection {c.get('uid', 'unknown')}. Using 0.")
                    return 0
            return 0

        current_ts = get_timestamp(conn)
        src_ip = conn['id.orig_h']
        dest_ip = conn['id.resp_h']
        service = conn['service']

        # Connexions récentes vers la même destination
        same_host_conns = [c for c in host_connections.get(src_ip, [])
                           if c['id.resp_h'] == dest_ip and
                           get_timestamp(c) >= current_ts - 2 and
                           get_timestamp(c) <= current_ts]

        # Connexions récentes vers le même service
        same_srv_conns = [c for c in srv_connections.get(service, [])
                          if get_timestamp(c) >= current_ts - 2 and
                          get_timestamp(c) <= current_ts]

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

    def monitor_real_time_logs(self, interval=60):
        """Surveille les logs Zeek en temps réel"""
        print(f"Surveillance des logs en temps réel démarrée. Intervalle: {interval} secondes")
        print(f"Répertoire de surveillance: {self.zeek_logs_dir}")
        print("Appuyez sur Ctrl+C pour arrêter...\n")

        # Initialiser l'ensemble des fichiers déjà traités
        self.processed_files = set()

        try:
            while True:
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Traitement des nouveaux logs...")

                # Extraire seulement les nouvelles connexions
                new_connections = self.extract_connection_data(real_time=True)

                if new_connections > 0:
                    # Écrire les nouvelles données dans le fichier CSV
                    self.write_to_csv()
                    print(f"Nombre de connexions extraites en temps réel: {new_connections}")
                    print(f"Données ajoutées au fichier CSV: {new_connections} enregistrements\n")
                else:
                    print("Aucune nouvelle connexion détectée depuis le dernier intervalle\n")

                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nSurveillance arrêtée par l'utilisateur.")

    def extract_real_time_connection_data(self):
        """
        Extrait les données de connexion depuis les logs en temps réel de Zeek.
        """
        import os

        # Vérifier que le répertoire des logs en temps réel existe
        if not os.path.exists(self.real_time_logs_dir):
            print(f"ERREUR: Le répertoire des logs en temps réel '{self.real_time_logs_dir}' n'existe pas.")
            return

        # Liste des fichiers log à traiter
        log_files = {
            'conn': 'conn.log',
            'dns': 'dns.log',
            'http': 'http.log',
            'ssh': 'ssh.log',
            'ssl': 'ssl.log',
            'files': 'files.log',
            'weird': 'weird.log',
            'notice': 'notice.log',
            'software': 'software.log',
            'ntp': 'ntp.log'
        }

        # Traiter d'abord le fichier conn.log pour établir les connexions de base
        conn_file = os.path.join(self.real_time_logs_dir, log_files['conn'])
        if os.path.exists(conn_file):
            conn_records = self.read_log_file(conn_file)

            for record in conn_records:
                if not record or 'uid' not in record:
                    continue

                ts = record.get('ts')
                # Valider le timestamp
                if not ts or '\x00' in ts or not ts.replace('.', '').replace('-', '').isdigit():
                    print(f"Skipping invalid timestamp '{ts}' for connection {record.get('uid', 'unknown')}")
                    continue

                uid = record['uid']
                # Ne pas traiter les connexions déjà traitées
                if uid in self.connections:
                    continue

                self.connections[uid] = {
                    'ts': ts,
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

        # Ensuite, enrichir avec les autres fichiers de log
        for log_type, file_name in log_files.items():
            if log_type == 'conn':  # Déjà traité
                continue

            file_path = os.path.join(self.real_time_logs_dir, file_name)
            if not os.path.exists(file_path):
                continue

            records = self.read_log_file(file_path)

            for record in conn_records:
                if not record or 'uid' not in record:
                    continue

                uid = record['uid']
                if uid in self.connections:
                    # Enrichir la connexion existante avec les données spécifiques au protocole
                    if log_type not in self.connections[uid]:
                        self.connections[uid][log_type] = []
                    self.connections[uid][log_type].append(record)

                    # Si le service n'est pas défini dans les données de connexion, le définir
                    if not self.connections[uid]['service'] and log_type in ['http', 'dns', 'ssh', 'ssl', 'ftp', 'smtp']:
                        self.connections[uid]['service'] = log_type

        print(f"Nombre de connexions extraites en temps réel: {len(self.connections)}")

    def append_to_nslkdd_file(self, nslkdd_records):
        """
        Ajoute les enregistrements NSL-KDD à un fichier CSV existant.
        Si le fichier n'existe pas, il est créé avec un en-tête.

        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        import os
        import csv

        file_exists = os.path.isfile(self.output_file)

        with open(self.output_file, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=self.nslkdd_attributes)
            if not file_exists:
                writer.writeheader()
            for record in nslkdd_records:
                writer.writerow(record)

    def enrich_data_for_elasticsearch(self, nslkdd_records):
        """
        Enrichit les données NSL-KDD avec des informations supplémentaires pour ElasticSearch.

        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD

        Returns:
            list: Liste de dictionnaires enrichis pour ElasticSearch
        """
        from datetime import datetime
        import socket

        enriched_records = []

        for i, record in enumerate(nslkdd_records):
            # Récupérer l'identifiant de connexion correspondant
            conn_id = list(self.connections.keys())[i] if i < len(self.connections) else None
            conn = self.connections.get(conn_id, {})

            # Créer un nouvel enregistrement enrichi
            enriched = record.copy()

            # Ajouter des informations temporelles
            ts = conn.get('ts')
            if ts and isinstance(ts, str):
                try:
                    timestamp = datetime.fromtimestamp(float(ts))
                    enriched['@timestamp'] = timestamp.isoformat()
                except (ValueError, TypeError):
                    print(f"Warning: Invalid timestamp '{ts}' for connection {conn_id}. Using current time.")
                    enriched['@timestamp'] = datetime.now().isoformat()
            else:
                enriched['@timestamp'] = datetime.now().isoformat()

            # Ajouter des informations réseau
            enriched['src_ip'] = conn.get('id.orig_h')
            enriched['src_port'] = conn.get('id.orig_p')
            enriched['dst_ip'] = conn.get('id.resp_h')
            enriched['dst_port'] = conn.get('id.resp_p')

            # Résolution DNS (optionnelle, peut être coûteux en performance)
            src_ip = conn.get('id.orig_h')
            dst_ip = conn.get('id.resp_h')
            try:
                if src_ip:
                    enriched['src_hostname'] = socket.getfqdn(src_ip)
                if dst_ip:
                    enriched['dst_hostname'] = socket.getfqdn(dst_ip)
            except:
                pass

            # Ajouter des informations de trafic réseau
            enriched['bytes_in'] = conn.get('orig_bytes')
            enriched['bytes_out'] = conn.get('resp_bytes')
            enriched['packets_in'] = conn.get('orig_pkts')
            enriched['packets_out'] = conn.get('resp_pkts')

            # Récupérer le nom du service depuis le mappage
            service = conn.get('service')
            if service:
                enriched['service_name'] = service
                enriched['service_mapped'] = self.service_mapping.get(service, 'other')

            # Ajouter l'identifiant unique de la connexion
            enriched['conn_uid'] = conn_id

            # Ajouter des informations d'état de connexion
            enriched['conn_state_desc'] = self.get_conn_state_description(conn.get('conn_state'))

            # Vérifier si la connexion contient des indicateurs de sécurité
            if 'notice' in conn:
                notices = [n.get('note') for n in conn['notice'] if n.get('note')]
                if notices:
                    enriched['security_notices'] = notices

            # Autres métadonnées
            enriched['source'] = 'zeek'
            enriched['event_type'] = 'network_connection'

            enriched_records.append(enriched)

        return enriched_records

    def get_conn_state_description(self, conn_state):
        """
        Retourne une description en langage naturel pour un état de connexion donné.

        Args:
            conn_state (str): État de connexion Zeek

        Returns:
            str: Description de l'état de connexion
        """
        descriptions = {
            'S0': "Tentative de connexion sans réponse",
            'SF': "Établissement et terminaison normale",
            'REJ': "Tentative de connexion rejetée",
            'S1': "Connexion établie, non terminée",
            'S2': "Connexion établie, tentative de fermeture par l'initiateur",
            'S3': "Connexion établie, tentative de fermeture par le destinataire",
            'RSTO': "Connexion établie, avortée par l'initiateur",
            'RSTR': "Connexion établie, avortée par le destinataire",
            'RSTOS0': "L'initiateur a envoyé un SYN suivi d'un RST",
            'SH': "L'initiateur a envoyé un SYN suivi d'un FIN",
            'OTH': "Pas de SYN, non fermée"
        }

        return descriptions.get(conn_state, "État inconnu")

    def store_in_elasticsearch(self, nslkdd_records):
        """
        Stocke les enregistrements NSL-KDD dans ElasticSearch.

        Args:
            nslkdd_records (list): Liste de dictionnaires contenant les caractéristiques NSL-KDD
        """
        try:
            from elasticsearch import Elasticsearch, helpers
            import urllib3
            import warnings

            # Désactiver les avertissements SSL
            urllib3.disable_warnings()
            warnings.filterwarnings('ignore')

            # Enrichir les données pour ElasticSearch
            es_records = self.enrich_data_for_elasticsearch(nslkdd_records)

            # Connexion à ElasticSearch
            es = Elasticsearch(
                self.es_config["url"],
                api_key=self.es_config["api_key"],
                verify_certs=False,
                ssl_show_warn=False
            )

            # Vérifier la connexion
            if not es.ping():
                print("ERREUR: Impossible de se connecter à ElasticSearch.")
                return

            # Préparation des données pour l'insertion en bloc
            actions = []
            for record in es_records:
                action = {
                    "_index": self.es_config["index"],
                    "_source": record
                }
                actions.append(action)

            # Insérer les données par lots
            if actions:
                # Diviser en lots si nécessaire
                batch_size = self.es_config["batch_size"]
                for i in range(0, len(actions), batch_size):
                    batch = actions[i:i+batch_size]
                    success, failed = helpers.bulk(es, batch, stats_only=True)
                    print(f"ElasticSearch: {success} documents indexés, {failed} échecs")

        except ImportError:
            print("ERREUR: Module Elasticsearch non disponible. Installez-le avec 'pip install elasticsearch'")
        except Exception as e:
            print(f"ERREUR lors de l'insertion dans ElasticSearch: {e}")


def main():
    """
    Fonction principale qui analyse les arguments de ligne de commande et exécute les actions appropriées.
    """
    import argparse
    import sys

    # Analyser les arguments de ligne de commande
    parser = argparse.ArgumentParser(description='Convertit les logs Zeek en format NSL-KDD pour les systèmes de détection d\'intrusion.')
    parser.add_argument('--logs-dir', type=str, default='/opt/zeek/logs',
                        help='Répertoire contenant les logs Zeek (par défaut: /opt/zeek/logs)')
    parser.add_argument('--output', type=str, default='nslkdd_format.csv',
                        help='Fichier de sortie au format NSL-KDD (par défaut: nslkdd_format.csv)')
    parser.add_argument('--real-time', action='store_true',
                        help='Surveiller les logs Zeek en temps réel')
    parser.add_argument('--interval', type=int, default=60,
                        help='Intervalle de surveillance en secondes (par défaut: 60)')
    parser.add_argument('--elasticsearch', action='store_true',
                        help='Intégrer les données dans ElasticSearch')

    args = parser.parse_args()

    # Créer le convertisseur avec les options spécifiées
    converter = ZeekToNSLKDD(
        zeek_logs_dir=args.logs_dir,
        output_file=args.output,
        real_time=args.real_time,
        es_integration=args.elasticsearch
    )

    # Exécuter l'action appropriée
    if args.real_time:
        # Mode de surveillance en temps réel
        converter.monitor_real_time_logs(interval=args.interval)
    else:
        # Mode de traitement par lots (existant)
        converter.convert()

if __name__ == "__main__":
    main()
