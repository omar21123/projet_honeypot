# honeypot.profile

#include <tunables/global>

# Profil pour le script honeypot.
# REMPLACEZ '/opt/honeypot/' par le chemin absolu de votre projet
nano /home/kali/Desktop/honeypot/apps/web/honeypot.profile {
  # Inclure les règles de base et pour python3
  #include <abstractions/base>
  #include <abstractions/python>

  # --- Fichiers du projet ---
  # Autoriser le script principal à être lu (r) et "mappé" en mémoire (m)
  /opt/honeypot/honeypot_app.py mr,
  # Autoriser la lecture du module seccomp
  /opt/honeypot/seccomp_config.py r,
  
  # --- Base de données ---
  # Accès en lecture/écriture (rw) à la base de données
  /opt/honeypot/database.db rw,

  # --- Uploads ---
  # Accès au dossier d'uploads (r) et aux fichiers dedans (rw)
  /opt/honeypot/uploads/ r,
  /opt/honeypot/uploads/* rw,

  # --- Logs ---
  # Accès en écriture (w) au fichier de log.
  # Le dossier /var/log/honeypot/ DOIT exister avant de lancer !
  /var/log/honeypot/ecom_honeypot.log w,

  # --- Réseau ---
  # Autorisations réseau pour Flask sur le port 5000
  network tcp bind,
  network tcp listen,
  network tcp accept,

  # --- Interdictions explicites ---
  # Même si seccomp bloque execve, AppArmor l'empêche aussi
  # au niveau du système de fichiers (x = exécuter).
  deny /bin/sh x,
  deny /bin/bash x,
  deny /bin/dash x,
  deny /usr/bin/perl x,
}
