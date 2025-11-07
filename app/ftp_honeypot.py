import socket
import threading
import json
import time

# Fichier où les logs JSON seront écrits
FTP_LOG_FILE = "honeypot_ftp.log"
HOST = '0.0.0.0'
PORT = 2121 # Port non standard 2121 (FTP standard est 21)

# --- Fonctions de Logging Honeypot (JSON) ---
def log_event(event_type, source_ip, command=None, username=None, password=None, message=""):
    """Crée une entrée de log JSON structurée pour l'activité FTP."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "honeypot_type": "ftp",
        "event_type": event_type,
        "source_ip": source_ip,
        "command": command,
        "username": username,
        "password": password,
        "message": message
    }
    try:
        with open(FTP_LOG_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"[-] Erreur d'écriture dans le log FTP: {e}")

# --- Gestion d'une Connexion FTP Individuelle ---
def handle_ftp_connection(conn, addr):
    """Gère le dialogue simple d'un client FTP."""
    source_ip = addr[0]
    username = "N/A"
    
    log_event(
        event_type="connection_established",
        source_ip=source_ip,
        message="Nouvelle connexion FTP entrante"
    )
    
    try:
        # Envoie le code de bienvenue FTP standard (220)
        conn.sendall(b"220 FTP Honeypot Service Ready.\r\n")
        
        while True:
            # Attend de recevoir une commande (USER, PASS, QUIT, etc.)
            data = conn.recv(1024).decode().strip()
            if not data:
                break
                
            command, *args = data.split(' ', 1)
            command = command.upper()
            arg = args[0] if args else ''

            log_event(
                event_type="command_received",
                source_ip=source_ip,
                command=command,
                message=f"Commande reçue: {command} {arg}"
            )
            
            if command == 'USER':
                username = arg
                # Réponse standard : demande le mot de passe (331)
                conn.sendall(b"331 Password required for " + username.encode() + b".\r\n")
            
            elif command == 'PASS':
                password = arg
                
                # Logue les identifiants capturés
                log_event(
                    event_type="login_attempt",
                    source_ip=source_ip,
                    username=username,
                    password=password,
                    message="Tentative d'identifiants FTP capturée."
                )
                
                # Réponse standard : échec d'authentification (530)
                conn.sendall(b"530 Login incorrect.\r\n")
                break 

            elif command == 'QUIT':
                conn.sendall(b"221 Goodbye.\r\n")
                break
            
            else:
                # Réponse par défaut pour les autres commandes
                conn.sendall(b"500 Command not understood.\r\n")

    except Exception as e:
        log_event(
            event_type="connection_error",
            source_ip=source_ip,
            message=f"Erreur de gestion de connexion FTP : {e}"
        )
    finally:
        conn.close()
        log_event(
            event_type="connection_closed",
            source_ip=source_ip,
            message="Connexion FTP fermee"
        )


# --- Fonction principale de démarrage du Honeypot ---
def start_ftp_honeypot(host=HOST, port=PORT):
    """Initialise le socket et démarre la boucle d'écoute."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5) 
        print(f"[*] FTP Honeypot écoutant sur {host}:{port}")

        while True:
            conn, addr = sock.accept()
            t = threading.Thread(target=handle_ftp_connection, args=(conn, addr))
            t.start()

    except Exception as e:
        print(f"[-] Erreur fatale lors du démarrage du serveur FTP : {e}")
        time.sleep(5)


if __name__ == '__main__':
    start_ftp_honeypot()
