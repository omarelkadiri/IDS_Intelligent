#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de conversion des données Zeek en format NSL-KDD pour IDS intelligent.
Ce script lit les journaux Zeek et génère des entrées au format compatible avec NSL-KDD.
"""

import os
import gzip
import json
import csv
import re
import datetime
import ipaddress
import math
from collections import defaultdict

# Constantes globales
TCP_FLAGS = {"OTH", "REJ", "RSTO", "RSTOS0", "RSTR", "S0", "S1", "S2", "S3", "SF", "SH"}
CONNECTION_WINDOW = 2  # Fenêtre de temps en secondes pour calculer les métriques de connexion

class ZeekToNSLKDD:
    """
    Classe principale pour convertir les données Zeek en format NSL-KDD
    """
    def __init__(self, zeek_logs_dir):
        """
        Initialisation de la classe
        
        Args:
            zeek_logs_dir (str): Chemin vers le répertoire contenant les journaux Zeek
        """
        self.zeek_logs_dir = zeek_logs_dir
        self.conn_data = {}  # Stockage des données de connexion
        self.host_stats = defaultdict(lambda: defaultdict(int))  # Statistiques par hôte
        self.service_stats = defaultdict(lambda: defaultdict(int))  # Statistiques par service
        
        # Mapping des services Zeek vers NSL-KDD
        self.service_mapping = {
            "http": "http",
            "https": "http_443",
            "dns": "domain",
            "ftp": "ftp",
            "ftp-data": "ftp_data",
            "ssh": "ssh",
            "smtp": "smtp",
            "imap": "imap4",
            "pop3": "pop_3",
            "telnet": "telnet",
            # Ajouter d'autres mappings si nécessaire
        }
        
        # Mappage des flags de connexion Zeek vers NSL-KDD
        self.flag_mapping = {
            "S0": "S0",  # Connexion initiée mais non établie
            "S1": "S1",  # Connexion établie et terminée
            "SF": "SF",  # Flux normal établi et terminé
            "REJ": "REJ",  # Connexion rejetée
            "S2": "S2",  # Connexion établie et close par l'initiateur
            "S3": "S3",  # Connexion établie et close par le répondeur
            "RSTO": "RSTO",  # Connexion reset par l'initiateur
            "RSTR": "RSTR",  # Connexion reset par le répondeur
            "RSTOS0": "RSTOS0",  # Initiateur a envoyé un SYN puis un RST
            "RSTRH": "RSTR",  # Répondeur a envoyé un SYN ACK puis un RST (mapped to closest)
            "SH": "SH",  # Initiateur a envoyé un SYN suivi d'un FIN
            "OTH": "OTH",  # Aucun des cas précédents
        }
        
        # Initialisation des compteurs pour les statistiques
        self.reset_stats()
    
    def reset_stats(self):
        """Réinitialise les compteurs de statistiques"""
        self.connections_past_2_seconds = []
        self.service_counts = defaultdict(int)
        self.error_counts = defaultdict(int)
        self.service_error_counts = defaultdict(lambda: defaultdict(int))
    
    def extract_zeek_logs(self):
        """
        Parcourt les fichiers de journaux Zeek et extrait les données pertinentes
        
        Returns:
            dict: Données de connexion agrégées
        """
        for filename in os.listdir(self.zeek_logs_dir):
            if not os.path.isfile(os.path.join(self.zeek_logs_dir, filename)):
                continue
                
            # Identifier le type de journal
            log_type = self._identify_log_type(filename)
            if not log_type:
                continue
                
            # Traiter selon le type de journal
            self._process_log_file(os.path.join(self.zeek_logs_dir, filename), log_type)
        
        # Traiter les connexions pour générer les statistiques
        self._process_connections()
        
        return self.conn_data
    
    def _identify_log_type(self, filename):
        """
        Identifie le type de journal Zeek à partir du nom de fichier
        
        Args:
            filename (str): Nom du fichier de journal
        
        Returns:
            str: Type de journal identifié ou None
        """
        if 'conn.' in filename:
            return 'conn'
        elif 'dns.' in filename:
            return 'dns'
        elif 'http.' in filename:
            return 'http'
        elif 'ssh.' in filename:
            return 'ssh'
        elif 'notice.' in filename:
            return 'notice'
        elif 'weird.' in filename:
            return 'weird'
        elif 'known_services.' in filename:
            return 'known_services'
        # Ajouter d'autres types si nécessaire
        return None
    
    def _process_log_file(self, file_path, log_type):
        """
        Traite un fichier de journal Zeek spécifique
        
        Args:
            file_path (str): Chemin vers le fichier de journal
            log_type (str): Type de journal
        """
        try:
            # Ouvre le fichier (compressé ou non)
            open_func = gzip.open if file_path.endswith('.gz') else open
            mode = 'rt' if file_path.endswith('.gz') else 'r'
            
            with open_func(file_path, mode) as f:
                # Lire et parser l'en-tête
                headers = []
                types = []
                
                for line in f:
                    line = line.strip()
                    
                    # Ignorer les lignes vides ou de commentaires génériques
                    if not line or line.startswith('#close'):
                        continue
                    
                    # Parser les en-têtes
                    if line.startswith('#fields'):
                        headers = line.split('\t')[1:]
                        continue
                    
                    if line.startswith('#types'):
                        types = line.split('\t')[1:]
                        continue
                    
                    # Si on a les en-têtes, commencer à traiter les données
                    if headers and not line.startswith('#'):
                        values = line.split('\t')
                        
                        # Vérifier que nous avons le bon nombre de valeurs
                        if len(values) == len(headers):
                            data = dict(zip(headers, values))
                            
                            # Traiter selon le type de journal
                            if log_type == 'conn':
                                self._process_conn_log(data)
                            elif log_type == 'dns':
                                self._process_dns_log(data)
                            elif log_type == 'http':
                                self._process_http_log(data)
                            elif log_type == 'ssh':
                                self._process_ssh_log(data)
                            elif log_type == 'notice':
                                self._process_notice_log(data)
                            elif log_type == 'weird':
                                self._process_weird_log(data)
                            elif log_type == 'known_services':
                                self._process_known_services_log(data)
        
        except Exception as e:
            print(f"Erreur lors du traitement du fichier {file_path}: {e}")
    
    def _process_conn_log(self, data):
        """
        Traite une entrée de journal de connexion
        
        Args:
            data (dict): Données de l'entrée du journal
        """
        # Extraire l'UID de connexion
        uid = data.get('uid', '')
        if not uid:
            return
            
        # Extraire les informations de base
        ts = float(data.get('ts', 0))
        orig_h = data.get('id.orig_h', '')
        orig_p = int(data.get('id.orig_p', 0))
        resp_h = data.get('id.resp_h', '')
        resp_p = int(data.get('id.resp_p', 0))
        proto = data.get('proto', '').lower()
        service = data.get('service', '')
        duration = float(data.get('duration', 0)) if data.get('duration', '-') != '-' else 0
        orig_bytes = int(data.get('orig_bytes', 0)) if data.get('orig_bytes', '-') != '-' else 0
        resp_bytes = int(data.get('resp_bytes', 0)) if data.get('resp_bytes', '-') != '-' else 0
        conn_state = data.get('conn_state', '')
        
        # Stocker les données de connexion
        self.conn_data[uid] = {
            'ts': ts,
            'uid': uid,
            'orig_h': orig_h,
            'orig_p': orig_p,
            'resp_h': resp_h,
            'resp_p': resp_p,
            'proto': proto,
            'service': service,
            'duration': duration,
            'orig_bytes': orig_bytes,
            'resp_bytes': resp_bytes,
            'conn_state': conn_state,
            # Champs NSL-KDD initialisés avec des valeurs par défaut
            'land': '0',
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': '0',
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': '0',
            'is_guest_login': '0',
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0,
            'class': 'normal'  # Par défaut, marqué comme normal
        }
        
        # Vérifier si l'origine et la destination sont identiques (land)
        if orig_h == resp_h and orig_p == resp_p:
            self.conn_data[uid]['land'] = '1'
        
        # Mapper le flag de connexion
        if conn_state in self.flag_mapping:
            self.conn_data[uid]['flag'] = self.flag_mapping[conn_state]
        else:
            self.conn_data[uid]['flag'] = 'OTH'  # Valeur par défaut
            
        # Mapper le service si possible
        if service in self.service_mapping:
            self.conn_data[uid]['service'] = self.service_mapping[service]
        else:
            # Si le service n'est pas trouvé dans le mapping, utiliser le port pour deviner
            if resp_p == 80:
                self.conn_data[uid]['service'] = 'http'
            elif resp_p == 443:
                self.conn_data[uid]['service'] = 'http_443'
            elif resp_p == 53:
                self.conn_data[uid]['service'] = 'domain'
            elif resp_p == 22:
                self.conn_data[uid]['service'] = 'ssh'
            elif resp_p == 21:
                self.conn_data[uid]['service'] = 'ftp'
            else:
                self.conn_data[uid]['service'] = 'other'
        
        # Mettre à jour les statistiques
        self.connections_past_2_seconds.append({
            'ts': ts,
            'orig_h': orig_h,
            'resp_h': resp_h,
            'resp_p': resp_p,
            'service': self.conn_data[uid]['service'],
            'error': 'REJ' in conn_state or 'RST' in conn_state
        })
        
        # Incrémenter les compteurs de statistiques hôte
        dst_ip = resp_h
        self.host_stats[dst_ip]['count'] += 1
        
        service_name = self.conn_data[uid]['service']
        self.host_stats[dst_ip]['services'][service_name] += 1
        
        if 'REJ' in conn_state or 'RST' in conn_state:
            self.host_stats[dst_ip]['errors'] += 1
            self.host_stats[dst_ip]['service_errors'][service_name] += 1
        
        # Incrémenter les compteurs de statistiques service
        self.service_stats[service_name]['count'] += 1
        if 'REJ' in conn_state or 'RST' in conn_state:
            self.service_stats[service_name]['errors'] += 1
    
    def _process_dns_log(self, data):
        """
        Traite une entrée de journal DNS
        
        Args:
            data (dict): Données de l'entrée du journal
        """
        uid = data.get('uid', '')
        if uid in self.conn_data:
            # Mettre à jour le service
            self.conn_data[uid]['service'] = 'domain'
            
            # Si requête DNS, marquer comme connexion normale
            if data.get('qtype_name', '') in ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'TXT']:
                self.conn_data[uid]['class'] = 'normal'
    
    def _process_http_log(self, data):
        """
        Traite une entrée de journal HTTP
        
        Args:
            data (dict): Données de l'entrée du journal
        """
        uid = data.get('uid', '')
        if uid in self.conn_data:
            # Mettre à jour le service
            port = data.get('id.resp_p', '')
            if port == '443':
                self.conn_data[uid]['service'] = 'http_443'
            else:
                self.conn_data[uid]['service'] = 'http'
            
            # Mettre à jour l'état de connexion (logged_in)
            if data.get('username', '-') != '-' and data.get('username', '-') != '':
                self.conn_data[uid]['logged_in'] = '1'
                
                # Vérifier si c'est un login invité
                username = data.get('username', '').lower()
                if username in ['guest', 'anonymous']:
                    self.conn_data[uid]['is_guest_login'] = '1'
            
            # Vérifier si la requête contient des éléments "hot" (potentiellement malveillants)
            uri = data.get('uri', '')
            if any(keyword in uri.lower() for keyword in ['/etc/', '/bin/', '/admin/', '/root/', 'password', 'admin', 'shell']):
                self.conn_data[uid]['hot'] += 1
    
    def _process_ssh_log(self, data):
        """
        Traite une entrée de journal SSH
        
        Args:
            data (dict): Données de l'entrée du journal
        """
        uid = data.get('uid', '')
        if uid in self.conn_data:
            # Mettre à jour le service
            self.conn_data[uid]['service'] = 'ssh'
            
            # Vérifier les tentatives d'authentification
            auth_success = data.get('auth_success', '-')
            auth_attempts = int(data.get('auth_attempts', 0)) if data.get('auth_attempts', '-') != '-' else 0
            
            if auth_success == 'false' and auth_attempts > 0:
                self.conn_data[uid]['num_failed_logins'] = auth_attempts
            elif auth_success == 'true':
                self.conn_data[uid]['logged_in'] = '1'
    
    def _process_notice_log(self, data):
        """
        Traite une entrée de journal de notification
        
        Args:
            data (dict): Données de l'entrée du journal
        """
        uid = data.get('uid', '')
        if uid in self.conn_data:
            # Vérifier le type de notification
            note = data.get('note', '')
            
            # Si la notification est liée à une activité suspecte, marquer comme anomalie
            if any(keyword in note.lower() for keyword in ['attack', 'exploit', 'scan', 'brute', 'overflow', 'suspicious']):
                self.conn_data[uid]['class'] = 'anomaly'
                self.conn_data[uid]['hot'] += 1
    
    def _process_weird_log(self, data):
        """
        Traite une entrée de journal d'anomalies
        
        Args:
            data (dict): Données de l'entrée du journal
        """
        uid = data.get('uid', '')
        if uid in self.conn_data:
            # Vérifier le type d'anomalie
            name = data.get('name', '')
            
            # Si l'anomalie est liée à un fragment incorrect
            if 'fragment' in name.lower():
                self.conn_data[uid]['wrong_fragment'] += 1
            
            # Si l'anomalie est liée à des paquets urgents
            if 'urgent' in name.lower():
                self.conn_data[uid]['urgent'] += 1
            
            # Si l'anomalie est potentiellement malveillante
            if any(keyword in name.lower() for keyword in ['overflow', 'exploit', 'bad', 'invalid']):
                self.conn_data[uid]['hot'] += 1
                self.conn_data[uid]['class'] = 'anomaly'
    
    def _process_known_services_log(self, data):
        """
        Traite une entrée de journal des services connus
        
        Args:
            data (dict): Données de l'entrée du journal
        """
        host = data.get('host', '')
        port = data.get('port_num', '')
        proto = data.get('port_proto', '').lower()
        service = data.get('service', '')
        
        # Mettre à jour les informations de service pour toutes les connexions associées
        for uid, conn in self.conn_data.items():
            if conn['resp_h'] == host and conn['resp_p'] == int(port) and conn['proto'] == proto:
                if service in self.service_mapping:
                    conn['service'] = self.service_mapping[service]
                else:
                    conn['service'] = 'other'
    
    def _process_connections(self):
        """
        Traite les connexions pour calculer les statistiques et caractéristiques avancées
        """
        # Nettoyer les connexions trop anciennes
        current_time = max([conn['ts'] for uid, conn in self.conn_data.items()]) if self.conn_data else 0
        self.connections_past_2_seconds = [
            conn for conn in self.connections_past_2_seconds 
            if current_time - conn['ts'] <= CONNECTION_WINDOW
        ]
        
        # Calculer les caractéristiques pour chaque connexion
        for uid, conn in self.conn_data.items():
            # Caractéristiques temporelles
            current_conn_time = conn['ts']
            
            # Filtrer les connexions dans la fenêtre temporelle
            recent_conns = [
                c for c in self.connections_past_2_seconds 
                if c['ts'] >= current_conn_time - CONNECTION_WINDOW and c['ts'] <= current_conn_time
            ]
            
            # Calculer count - nombre de connexions au même hôte cible dans les 2 dernières secondes
            same_host_conns = [c for c in recent_conns if c['resp_h'] == conn['resp_h']]
            conn['count'] = len(same_host_conns)
            
            # Calculer srv_count - nombre de connexions au même service dans les 2 dernières secondes
            same_service_conns = [c for c in recent_conns if c['service'] == conn['service']]
            conn['srv_count'] = len(same_service_conns)
            
            # Calculer les taux d'erreurs
            if conn['count'] > 0:
                # serror_rate - % de connexions avec des erreurs SYN
                serr_conns = [c for c in same_host_conns if c['error']]
                conn['serror_rate'] = len(serr_conns) / conn['count'] if conn['count'] > 0 else 0
                
                # rerror_rate - % de connexions avec des erreurs REJ
                rerr_conns = [c for c in same_host_conns if c['error']]
                conn['rerror_rate'] = len(rerr_conns) / conn['count'] if conn['count'] > 0 else 0
                
                # same_srv_rate - % de connexions au même service
                conn['same_srv_rate'] = len([c for c in same_host_conns if c['service'] == conn['service']]) / conn['count'] if conn['count'] > 0 else 0
                
                # diff_srv_rate - % de connexions à différents services
                conn['diff_srv_rate'] = 1 - conn['same_srv_rate']
            
            if conn['srv_count'] > 0:
                # srv_serror_rate - % de connexions au même service avec des erreurs SYN
                srv_serr_conns = [c for c in same_service_conns if c['error']]
                conn['srv_serror_rate'] = len(srv_serr_conns) / conn['srv_count'] if conn['srv_count'] > 0 else 0
                
                # srv_rerror_rate - % de connexions au même service avec des erreurs REJ
                srv_rerr_conns = [c for c in same_service_conns if c['error']]
                conn['srv_rerror_rate'] = len(srv_rerr_conns) / conn['srv_count'] if conn['srv_count'] > 0 else 0
                
                # srv_diff_host_rate - % de connexions au même service vers différents hôtes
                conn['srv_diff_host_rate'] = len(set([c['resp_h'] for c in same_service_conns])) / conn['srv_count'] if conn['srv_count'] > 0 else 0
            
            # Caractéristiques basées sur l'hôte
            dst_ip = conn['resp_h']
            
            # dst_host_count - nombre de connexions vers le même hôte cible
            conn['dst_host_count'] = self.host_stats[dst_ip]['count']
            
            service_name = conn['service']
            # dst_host_srv_count - nombre de connexions vers le même service sur l'hôte cible
            conn['dst_host_srv_count'] = self.host_stats[dst_ip]['services'][service_name]
            
            # Calculer les taux
            if conn['dst_host_count'] > 0:
                # dst_host_same_srv_rate - % de connexions au même service sur l'hôte cible
                conn['dst_host_same_srv_rate'] = conn['dst_host_srv_count'] / conn['dst_host_count']
                
                # dst_host_diff_srv_rate - % de connexions à différents services sur l'hôte cible
                conn['dst_host_diff_srv_rate'] = 1 - conn['dst_host_same_srv_rate']
                
                # dst_host_serror_rate - % de connexions à l'hôte cible avec des erreurs SYN
                conn['dst_host_serror_rate'] = self.host_stats[dst_ip]['errors'] / conn['dst_host_count']
            
            if conn['dst_host_srv_count'] > 0:
                # dst_host_srv_serror_rate - % de connexions au même service sur l'hôte cible avec des erreurs SYN
                conn['dst_host_srv_serror_rate'] = self.host_stats[dst_ip]['service_errors'][service_name] / conn['dst_host_srv_count']
                
                # dst_host_rerror_rate et dst_host_srv_rerror_rate (pour simplifier, utiliser les mêmes valeurs)
                conn['dst_host_rerror_rate'] = conn['dst_host_serror_rate']
                conn['dst_host_srv_rerror_rate'] = conn['dst_host_srv_serror_rate']
            
            # dst_host_same_src_port_rate - % de connexions au même port source vers l'hôte cible
            # Nécessite des calculs supplémentaires non effectués ici
            conn['dst_host_same_src_port_rate'] = 0.0
            
            # dst_host_srv_diff_host_rate - % de connexions au même service vers différents hôtes
            conn['dst_host_srv_diff_host_rate'] = conn['srv_diff_host_rate']
    
    def get_nslkdd_data(self):
        """
        Convertit les données Zeek au format NSL-KDD
        
        Returns:
            list: Liste des entrées au format NSL-KDD
        """
        nslkdd_data = []
        
        for uid, conn in self.conn_data.items():
            # Préparer l'entrée NSL-KDD
            entry = {
                'duration': conn['duration'],
                'protocol_type': conn['proto'],
                'service': conn['service'],
                'flag': conn['flag'],
                'src_bytes': conn['orig_bytes'],
                'dst_bytes': conn['resp_bytes'],
                'land': conn['land'],
                'wrong_fragment': conn['wrong_fragment'],
                'urgent': conn['urgent'],
                'hot': conn['hot'],
                'num_failed_logins': conn['num_failed_logins'],
                'logged_in': conn['logged_in'],
                'num_compromised': conn['num_compromised'],
                'root_shell': conn['root_shell'],
                'su_attempted': conn['su_attempted'],
                'num_root': conn['num_root'],
                'num_file_creations': conn['num_file_creations'],
                'num_shells': conn['num_shells'],
                'num_access_files': conn['num_access_files'],
                'num_outbound_cmds': conn['num_outbound_cmds'],
                'is_host_login': conn['is_host_login'],
                'is_guest_login': conn['is_guest_login'],
                'count': conn['count'],
                'srv_count': conn['srv_count'],
                'serror_rate': conn['serror_rate'],
                'srv_serror_rate': conn['srv_serror_rate'],
                'rerror_rate': conn['rerror_rate'],
                'srv_rerror_rate': conn['srv_rerror_rate'],
                'same_srv_rate': conn['same_srv_rate'],
                'diff_srv_rate': conn['diff_srv_rate'],
                'srv_diff_host_rate': conn['srv_diff_host_rate'],
                'dst_host_count': conn['dst_host_count'],
                'dst_host_srv_count': conn['dst_host_srv_count'],
                'dst_host_same_srv_rate': conn['dst_host_same_srv_rate'],
                'dst_host_diff_srv_rate': conn['dst_host_diff_srv_rate'],
                'dst_host_same_src_port_rate': conn['dst_host_same_src_port_rate'],
                'dst_host_srv_diff_host_rate': conn['dst_host_srv_diff_host_rate'],
                'dst_host_serror_rate': conn['dst_host_serror_rate'],
                'dst_host_srv_serror_rate': conn['dst_host_srv_serror_rate'],
                'dst_host_rerror_rate': conn['dst_host_rerror_rate'],
                'dst_host_srv_rerror_rate': conn['dst_host_srv_rerror_rate'],
                'class': conn['class']
            }
            
            nslkdd_data.append(entry)
        
        return nslkdd_data
    
    def save_to_csv(self, output_file):
        """
        Sauvegarde les données au format CSV NSL-KDD
        
        Args:
            output_file (str): Chemin vers le fichier de sortie
        """
        nslkdd_data = self.get_nslkdd_data()
        
        if not nslkdd_data:
            print("Aucune donnée à sauvegarder.")
            return
        
        # Définir les champs dans l'ordre NSL-KDD
        fieldnames = [
            'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
            'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
            'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
            'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
            'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
            'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
            'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
            'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
            'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
            'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class'
        ]
        
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for entry in nslkdd_data:
                writer.writerow(entry)
                
        print(f"Données sauvegardées dans {output_file}")
        
    def extract_missing_features(self):
        """
        Identifie et liste les caractéristiques NSL-KDD non directement fournies par Zeek
        
        Returns:
            dict: Dictionnaire des caractéristiques manquantes et leurs descriptions
        """
        missing_features = {
            'hot': "Nombre d'indicateurs 'hot' (accès à des fichiers système, création de programmes, etc.)",
            'num_failed_logins': "Nombre de tentatives de connexion échouées",
            'logged_in': "1 si la connexion a réussi, 0 sinon",
            'num_compromised': "Nombre de conditions 'compromised' (accès root, fichiers modifiés, etc.)",
            'root_shell': "1 si un shell root a été obtenu, 0 sinon",
            'su_attempted': "1 si la commande 'su root' a été tentée, 0 sinon",
            'num_root': "Nombre d'accès en tant que root",
            'num_file_creations': "Nombre de créations de fichiers",
            'num_shells': "Nombre de shells démarrés",
            'num_access_files': "Nombre d'opérations sur des fichiers de contrôle d'accès",
            'num_outbound_cmds': "Nombre de commandes sortantes dans une session FTP",
            'is_host_login': "1 si la connexion appartient à la liste 'hot', 0 sinon",
            'is_guest_login': "1 si la connexion est une connexion invité, 0 sinon",
            'dst_host_same_src_port_rate': "% de connexions au même port source vers l'hôte destination",
            'srv_diff_host_rate': "% de connexions vers le même service mais vers différents hôtes"
        }
        
        return missing_features


def main():
    """
    Fonction principale pour exécuter la conversion des logs Zeek en format NSL-KDD
    """
    import argparse
    
    parser = argparse.ArgumentParser(description='Convertir les logs Zeek en format NSL-KDD')
    parser.add_argument('--logs_dir', type=str, required=True, help='Répertoire contenant les logs Zeek')
    parser.add_argument('--output', type=str, required=True, help='Fichier CSV de sortie')
    
    args = parser.parse_args()
    
    # Créer une instance du convertisseur
    converter = ZeekToNSLKDD(args.logs_dir)
    
    # Extraire les données Zeek
    print("Extraction des données Zeek...")
    converter.extract_zeek_logs()
    
    # Sauvegarder au format NSL-KDD
    print("Conversion au format NSL-KDD...")
    converter.save_to_csv(args.output)
    
    # Afficher les caractéristiques manquantes
    print("\nCaractéristiques NSL-KDD non directement fournies par Zeek:")
    missing = converter.extract_missing_features()
    for feature, description in missing.items():
        print(f"- {feature}: {description}")
    
    print("\nTerminé. Vérifiez le fichier de sortie pour les résultats.")


if __name__ == "__main__":
    main()