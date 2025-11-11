import paramiko
import threading
import json
import time
import socket
import sys

# Fichier où les logs JSON seront écrits
SSH_LOG_FILE = "honeypot_ssh.log"
HOST_KEY_PATH = "host_rsa.key" # Clé générée par ssh-keygen

# --- Fonctions de Logging Honeypot (JSON) ---
def log_event(event_type, source_ip, username=None, password=None, command=None, message=""):
    """Crée une entrée de log JSON structurée pour l'activité SSH."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "honeypot_type": "ssh",
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "password": password,
        "command": command,
        "message": message
    }
    try:
        with open(SSH_LOG_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        # En cas d'erreur d'écriture (ex: permission), imprime dans la console d'erreur
        print(f"[-] Erreur d'écriture dans le log SSH: {e}", file=sys.stderr)

# --- Classe pour simuler la session Shell ---
class SSHSession:
    """Gère le shell leurre pour capturer les commandes."""
    def __init__(self, conn, server_addr):
        self.conn = conn
        self.server_addr = server_addr

    def start(self, chan):
        """Démarre le dialogue shell."""
        # Envoie le message d'accueil et le prompt
        chan.send(b"Welcome to the multi-honeypot shell!\r\n")
        chan.send(b"WARNING: This is a restricted system.\r\n")
        
        prompt = b"\r\n$ "
        chan.send(prompt)

        # Boucle de lecture des commandes
        while True:
            try:
                # Lit la commande envoyée par l'attaquant
                # Le code est en Python, mais l'interaction se fait via le protocole SSH
                command_bytes = chan.recv(1024)
                if not command_bytes:
                    break
                
                command = command_bytes.decode('utf-8').strip()
                
                # Logue la commande capturée (le but de cette classe)
                log_event(
                    event_type="command_executed",
                    source_ip=self.server_addr[0],
                    command=command,
                    message=f"Commande capturée: {command}"
                )
                
                # Simule une réponse pour ne pas alerter l'attaquant
                if command.lower() == 'exit':
                    break
                
                # Simule le résultat de la commande
                response = f"\r\nCommand '{command}' not allowed on this system.\r\n"
                chan.send(response.encode('utf-8'))
                
                # Renvoie le prompt
                chan.send(prompt)
                
            except EOFError:
                break
            except Exception:
                break
            
        chan.close()


# --- Classe Server Paramiko ---
class SSHHoneypot(paramiko.ServerInterface):
    """Implémentation du serveur SSH, hérite de paramiko.ServerInterface."""
    def __init__(self, addr):
        self.event = threading.Event()
        self.addr = addr 

    def check_auth_password(self, username, password):
        """Appelée lorsque le client tente une connexion par mot de passe."""
        # 1. Loguez la tentative de connexion
        log_event(
            event_type="login_attempt",
            source_ip=self.addr[0],
            username=username,
            password=password,
            message="Tentative d'authentification par mot de passe capturée."
        )
        # 2. Simule le succès (AUTH_SUCCESSFUL) pour autoriser la création du shell leurre
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        # Autorise seulement l'authentification par mot de passe
        return 'password'

    def check_channel_request(self, kind, chanid):
        """Vérifie si le client demande un shell (session)."""
        if kind == 'session':
            # Permet l'ouverture d'une session (shell) pour capturer les commandes
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_publickey(self, username, key):
        # Refuse l'authentification par clé publique
        return paramiko.AUTH_FAILED
    
    def check_channel_exec_request(self, channel, command):
        """Capture les commandes d'exécution directe (non interactive)."""
        log_event(
            event_type="command_direct",
            source_ip=self.addr[0],
            command=command.decode('utf-8'),
            message="Commande d'exécution directe capturée."
        )
        return True # Simule l'exécution

    def check_channel_shell_request(self, channel):
        """Appelée lorsque le client demande un shell. On lance notre shell leurre."""
        session = SSHSession(self.conn, self.addr)
        session.start(channel)
        return True

# --- Fonction de gestion d'une connexion SSH individuelle ---
def handle_ssh_connection(conn, addr, host_key):
    transport = paramiko.Transport(conn)
    
    try:
        transport.add_server_key(host_key)
        server = SSHHoneypot(addr)
        
        log_event(
            event_type="connection_established",
            source_ip=addr[0],
            message="Nouvelle connexion SSH entrante"
        )
        
        transport.start_server(server=server)
        
        # Le transport reste ouvert tant que le client n'a pas fermé le canal
        server.event.wait(600)  
        
        log_event(
            event_type="connection_closed",
            source_ip=addr[0],
            message="Connexion SSH fermée"
        )
        
    except Exception as e:
        log_event(
            event_type="connection_error",
            source_ip=addr[0],
            message=f"Erreur de gestion de connexion : {e}"
        )
    finally:
        transport.close()


# --- Fonction principale de démarrage du Honeypot ---
def start_ssh_honeypot(host="0.0.0.0", port=2222):
    """Initialise le socket et démarre la boucle d'écoute."""
    try:
        # Tente de charger la clé hôte
        host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)

        # Création du socket TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100) 
        print(f"[*] SSH Honeypot écoutant sur {host}:{port} (Capture de commandes active)")

        # Boucle d'acceptation des connexions (multithreading)
        while True:
            conn, addr = sock.accept()
            # Lance la gestion de la connexion dans un thread séparé
            t = threading.Thread(target=handle_ssh_connection, args=(conn, addr, host_key))
            t.start()

    except FileNotFoundError:
        # Affiche une erreur si la clé n'est pas générée
        print(f"[-] ERREUR: Clé hôte SSH non trouvée. Veuillez exécuter 'ssh-keygen -t rsa -f {HOST_KEY_PATH}' d'abord.", file=sys.stderr)
    except Exception as e:
        print(f"[-] Erreur fatale lors du démarrage du serveur SSH : {e}", file=sys.stderr)
        time.sleep(5)


if __name__ == '__main__':
    start_ssh_honeypot()