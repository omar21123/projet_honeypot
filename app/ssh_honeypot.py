import os
import paramiko
import threading
import json
import time
import socket
import sys

# ============================================================
#   LOGS → dossier commun "../logs"
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # /.../projet_honeypot_final/app
LOG_DIR = os.path.join(os.path.dirname(BASE_DIR), "logs")      # /.../projet_honeypot_final/logs
os.makedirs(LOG_DIR, exist_ok=True)

SSH_LOG_FILE = os.path.join(LOG_DIR, "honeypot_ssh.log")
HOST_KEY_PATH = "host_rsa.key"  # Clé générée par ssh-keygen dans app/


# ============================================================
#   Logging JSON
# ============================================================

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
        print(f"[-] Erreur d'écriture dans le log SSH: {e}", file=sys.stderr)


# ============================================================
#   Session shell factice
# ============================================================

class SSHSession:
    """Gère le shell leurre pour capturer les commandes."""
    def __init__(self, conn, server_addr):
        self.conn = conn
        self.server_addr = server_addr

    def start(self, chan):
        """Démarre le dialogue shell."""
        chan.send(b"Welcome to the multi-honeypot shell!\r\n")
        chan.send(b"WARNING: This is a restricted system.\r\n")
        
        prompt = b"\r\n$ "
        chan.send(prompt)

        while True:
            try:
                command_bytes = chan.recv(1024)
                if not command_bytes:
                    break
                
                command = command_bytes.decode('utf-8').strip()

                log_event(
                    event_type="command_executed",
                    source_ip=self.server_addr[0],
                    command=command,
                    message=f"Commande capturée: {command}"
                )

                if command.lower() == 'exit':
                    break

                response = f"\r\nCommand '{command}' not allowed on this system.\r\n"
                chan.send(response.encode('utf-8'))
                chan.send(prompt)

            except EOFError:
                break
            except Exception:
                break
            
        chan.close()


# ============================================================
#   Serveur SSH Paramiko
# ============================================================

class SSHHoneypot(paramiko.ServerInterface):
    def __init__(self, addr):
        self.event = threading.Event()
        self.addr = addr 

    def check_auth_password(self, username, password):
        log_event(
            event_type="login_attempt",
            source_ip=self.addr[0],
            username=username,
            password=password,
            message="Tentative d'authentification par mot de passe capturée."
        )
        return paramiko.AUTH_SUCCESSFUL
    
    def get_allowed_auths(self, username):
        return 'password'

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED
    
    def check_channel_exec_request(self, channel, command):
        log_event(
            event_type="command_direct",
            source_ip=self.addr[0],
            command=command.decode('utf-8'),
            message="Commande d'exécution directe capturée."
        )
        return True

    def check_channel_shell_request(self, channel):
        session = SSHSession(self.conn, self.addr)
        session.start(channel)
        return True


# ============================================================
#   Gestion des connexions SSH
# ============================================================

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


# ============================================================
#   Lancement du serveur SSH Honeypot
# ============================================================

def start_ssh_honeypot(host="0.0.0.0", port=2222):
    try:
        host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(100)

        print(f"[*] SSH Honeypot écoutant sur {host}:{port}")

        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_ssh_connection, args=(conn, addr, host_key))
            t.start()

    except FileNotFoundError:
        print(f"[-] ERREUR: Clé hôte SSH non trouvée. Exécute 'ssh-keygen -t rsa -f {HOST_KEY_PATH}'", file=sys.stderr)
    except Exception as e:
        print(f"[-] Erreur fatale lors du démarrage du serveur SSH : {e}", file=sys.stderr)
        time.sleep(5)


if __name__ == '__main__':
    start_ssh_honeypot()
