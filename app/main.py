from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import json
import time 
import os 
import threading 

# --- Configuration Globale de l'Application ---
app = Flask(__name__)
app.secret_key = "kimperi" 

# Configuration SQLAlchemy : Utilisation du nom d'origine pour la clarté
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db" # <--- Ceci est la base de données unique
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# Configuration des fichiers de logs (ils seront créés dans le répertoire racine du projet)
HTTP_LOG_FILE = "honeypot_http.log"
SSH_LOG_FILE = "honeypot_ssh.log" 

# --- Modèle de Base de Données ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# --- Fonctions de Logging Honeypot (JSON) ---
def log_http_event(source_ip, path, method, username=None, password=None, message=""):
    """Crée une entrée de log JSON pour l'activité HTTP/Web."""
    log_entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "honeypot_type": "http",
        "source_ip": source_ip,
        "path": path,
        "method": method,
        "username": username,
        "password": password,
        "message": message
    }
    try:
        # Écrit la ligne JSON dans le fichier de log HTTP
        with open(HTTP_LOG_FILE, 'a') as f:
            f.write(json.dumps(log_entry) + '\n')
    except Exception as e:
        # En cas d'erreur (souvent de permission), imprime dans la console
        print(f"Erreur d'écriture dans le log HTTP: {e}")


# --- Routes de l'Application Web (Connexion / Dashboard) ---

@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for('dashboard'))
    return render_template("index.html")

# Login
@app.route("/login", methods=["POST"])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['username'] = username
        return redirect(url_for('dashboard'))
    else:
        return render_template("index.html", error="Utilisateur ou mot de passe introuvable ou incorrect.")

# Register
@app.route("/register", methods=["POST"])
def register():
    username = request.form['username']
    password = request.form['password']
    
    user = User.query.filter_by(username=username).first()
    
    if user:
        return render_template("index.html", error="Cet utilisateur existe déjà !")
    else:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('dashboard'))

# Dashboard
@app.route("/dashboard")
def dashboard():
    if "username" in session:
        return render_template("dashboard.html", username=session['username'])
    return redirect(url_for('home'))

# Logout
@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# --- Route Honeypot HTTP/WEB ---

# Utilise une URL d'apparence légitime pour attirer les scanners.
@app.route("/admin/login", methods=["GET", "POST"]) 
@app.route("/admin", methods=["GET", "POST"])       
def http_honeypot():
    # Tente de récupérer l'adresse IP réelle (utile si derrière un proxy)
    source_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
    
    if request.method == 'POST':
        # Simule l'échec et log les identifiants tentés
        username = request.form.get('username', 'N/A')
        password = request.form.get('password', 'N/A')
        
        log_http_event(
            source_ip=source_ip,
            path=request.path,
            method="POST",
            username=username,
            password=password,
            message="Tentative d'authentification par force brute ou dictionnaire."
        )
        
        # Réponse pour simuler l'échec
        return render_template("honeypot_http_login.html", error="Nom d'utilisateur ou mot de passe incorrect. Réessayez.")

    # Log de la simple visite de la page
    log_http_event(
        source_ip=source_ip,
        path=request.path,
        method="GET",
        message="Visite simple de la page de login."
    )
    
    # Renvoyer le faux template
    return render_template("honeypot_http_login.html")


# --- Démarrage ---

if __name__ == "__main__":
    
    # Création de la base de données
    with app.app_context():
        try:
            db.create_all()
            print("[INFO] Base de données 'users.db' vérifiée/créée.")
        except Exception as e:
            print(f"[ERREUR FATALE] Impossible de créer la base de données: {e}")
    
    # Démarrer le serveur Flask 
    print("[INFO] Honeypot HTTP/Web actif sur /admin/login.")
    print("[TODO] Lancez votre script 'ssh_honeypot.py' séparément.")
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)