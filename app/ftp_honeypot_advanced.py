import os
import socket
import threading
import json
import time
import uuid

# --- Répertoire des logs commun (../logs) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))          # .../projet_honeypot_final/app
LOG_DIR = os.path.join(os.path.dirname(BASE_DIR), "logs")      # .../projet_honeypot_final/logs
os.makedirs(LOG_DIR, exist_ok=True)

# Fichier où les logs JSON seront écrits
FTP_LOG_FILE = os.path.join(LOG_DIR, "honeypot_ftp.log")
HOST = '0.0.0.0'
PORT = 2121  # Port non standard 2121 (FTP standard = 21)

# --- Fonctions de Logging Honeypot (JSON) ---
def log_event(event_type, source_ip, session_id=None, command=None,
              username=None, password=None, message="", extra=None):
    """Crée une entrée de log JSON structurée pour l'activité FTP."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "honeypot_type": "ftp",
        "event_type": event_type,
        "source_ip": source_ip,
        "session_id": session_id,
        "command": command,
        "username": username,
        "password": password,
        "message": message,
        "extra": extra or {}
    }
    try:
        with open(FTP_LOG_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        print(f"[-] Erreur d'écriture dans le log FTP: {e}")


# --- Gestion d'une Connexion FTP Individuelle (version avancée) ---
def handle_ftp_connection(conn, addr):
    """Gère le dialogue avancé d'un client FTP."""
    source_ip = addr[0]
    session_id = str(uuid.uuid4())  # ID unique par connexion
    username = "anonymous"
    authenticated = False
    current_dir = "/"

    # Petit système de fichiers factice
    fake_fs = {
        "/": ["pub", "secret", "readme.txt"],
        "/pub": ["file1.txt", "file2.log"],
        "/secret": ["admin_creds.txt", "db_backup.sql"]
    }

    conn.settimeout(300)  # Timeout de session pour éviter les connexions zombies

    log_event(
        event_type="connection_established",
        source_ip=source_ip,
        session_id=session_id,
        message="Nouvelle connexion FTP entrante (avancé)"
    )

    try:
        # Bannière plus “réaliste”
        conn.sendall(b"220 (FakeFTP 1.0) FTP Honeypot Service Ready.\r\n")

        buffer = ""

        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break

            buffer += chunk.decode(errors="ignore")

            # On traite ligne par ligne (cas où plusieurs commandes arrivent d'un coup)
            while "\r\n" in buffer:
                line, buffer = buffer.split("\r\n", 1)
                data = line.strip()
                if not data:
                    continue

                # Exemple : "USER root"
                parts = data.split(" ", 1)
                command = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                log_event(
                    event_type="command_received",
                    source_ip=source_ip,
                    session_id=session_id,
                    command=command,
                    message=f"Commande reçue: {data}",
                    extra={"raw": data, "current_dir": current_dir}
                )

                # ---- Gestion des commandes ----

                # Authentification
                if command == "USER":
                    username = arg or "anonymous"
                    conn.sendall(
                        f"331 Password required for {username}.\r\n".encode()
                    )

                elif command == "PASS":
                    password = arg

                    # Logue les identifiants capturés
                    log_event(
                        event_type="login_attempt",
                        source_ip=source_ip,
                        session_id=session_id,
                        username=username,
                        password=password,
                        message="Tentative d'identifiants FTP capturée."
                    )

                    # Pour le honeypot, on fait semblant que le login est OK
                    authenticated = True
                    conn.sendall(b"230 User logged in, proceed.\r\n")

                # Info système
                elif command == "SYST":
                    conn.sendall(b"215 UNIX Type: L8\r\n")

                elif command == "FEAT":
                    # On fait semblant de supporter quelques features
                    conn.sendall(
                        b"211-Features:\r\n"
                        b" MDTM\r\n"
                        b" SIZE\r\n"
                        b" UTF8\r\n"
                        b"211 End\r\n"
                    )

                # Ping/keep-alive
                elif command == "NOOP":
                    conn.sendall(b"200 NOOP ok.\r\n")

                # Répertoire courant
                elif command == "PWD":
                    conn.sendall(
                        f'257 "{current_dir}" is current directory.\r\n'.encode()
                    )

                # Changement de répertoire
                elif command == "CWD":
                    target = arg.strip() or "/"
                    # Normalisation ultra simple pour le TP
                    if not target.startswith("/"):
                        if current_dir.endswith("/"):
                            target = current_dir + target
                        else:
                            target = current_dir + "/" + target

                    # On ne vérifie que les clés existantes dans fake_fs
                    if target in fake_fs:
                        current_dir = target
                        conn.sendall(
                            f'250 Directory successfully changed to "{current_dir}".\r\n'.encode()
                        )
                    else:
                        conn.sendall(b"550 Failed to change directory.\r\n")

                # LIST (simulé sur le canal de contrôle, pas de data channel)
                elif command == "LIST":
                    conn.sendall(b"150 Opening ASCII mode data connection for file list.\r\n")

                    entries = fake_fs.get(current_dir, [])
                    # On loggue ce qu'on “présente”
                    log_event(
                        event_type="directory_list",
                        source_ip=source_ip,
                        session_id=session_id,
                        command="LIST",
                        message=f"LIST sur {current_dir}",
                        extra={"entries": entries}
                    )

                    # Format très simplifié du listing
                    for e in entries:
                        line = f"-rw-r--r-- 1 root root 1234 Jan 01 00:00 {e}\r\n"
                        conn.sendall(line.encode())

                    conn.sendall(b"226 Transfer complete.\r\n")

                # Téléchargement (RETR) – on ne renvoie rien, on log juste
                elif command == "RETR":
                    filename = arg.strip()
                    log_event(
                        event_type="file_access_attempt",
                        source_ip=source_ip,
                        session_id=session_id,
                        command="RETR",
                        message=f"Tentative de RETR sur {filename}",
                        extra={"current_dir": current_dir}
                    )
                    conn.sendall(b"550 File not available.\r\n")

                # Upload (STOR) – idem
                elif command == "STOR":
                    filename = arg.strip()
                    log_event(
                        event_type="file_upload_attempt",
                        source_ip=source_ip,
                        session_id=session_id,
                        command="STOR",
                        message=f"Tentative de STOR sur {filename}",
                        extra={"current_dir": current_dir}
                    )
                    conn.sendall(b"550 Permission denied.\r\n")

                # Déconnexion propre
                elif command == "QUIT":
                    conn.sendall(b"221 Goodbye.\r\n")
                    log_event(
                        event_type="client_quit",
                        source_ip=source_ip,
                        session_id=session_id,
                        command="QUIT",
                        message="Client a envoyé QUIT."
                    )
                    return  # on sort de la fonction → finally() va fermer

                # Commandes non supportées
                else:
                    conn.sendall(b"502 Command not implemented.\r\n")

    except socket.timeout:
        log_event(
            event_type="connection_timeout",
            source_ip=source_ip,
            session_id=session_id,
            message="Session FTP expirée (timeout)."
        )
    except Exception as e:
        log_event(
            event_type="connection_error",
            source_ip=source_ip,
            session_id=session_id,
            message=f"Erreur de gestion de connexion FTP : {e}"
        )
    finally:
        conn.close()
        log_event(
            event_type="connection_closed",
            source_ip=source_ip,
            session_id=session_id,
            message="Connexion FTP fermée."
        )


# --- Fonction principale de démarrage du Honeypot ---
def start_ftp_honeypot(host=HOST, port=PORT):
    """Initialise le socket et démarre la boucle d'écoute."""
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, port))
            sock.listen(5)
            print(f"[*] FTP Honeypot avancé écoutant sur {host}:{port}")

            while True:
                conn, addr = sock.accept()
                t = threading.Thread(target=handle_ftp_connection, args=(conn, addr), daemon=True)
                t.start()

        except Exception as e:
            print(f"[-] Erreur fatale lors du démarrage du serveur FTP : {e}")
            time.sleep(5)  # on attend avant de retenter


if __name__ == '__main__':
    start_ftp_honeypot()
