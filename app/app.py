#!/usr/bin/env python3
from flask import Flask, request, render_template_string, redirect, session, url_for, send_from_directory
import sqlite3, os, logging, json
from datetime import datetime
import seccomp_config

app = Flask(__name__)
app.secret_key = 'supersecretkey123'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('/home/kali/Desktop/projet_honeypot', exist_ok=True)

# Logging JSON pour ELK
logging.basicConfig(
    filename='/home/kali/Desktop/projet_honeypot/logs/ecom_honeypot.log',
    level=logging.INFO,
    format='%(message)s'
)
def log_event(event_type, details=None):
    entry = {
        '@timestamp': datetime.utcnow().isoformat() + 'Z',
        'honeypot': 'ecommerce',
        'event_type': event_type,
        'src_ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'method': request.method,
        'path': request.path,
        'query': request.args.to_dict(),
        'form': request.form.to_dict() if request.form else {},
        'details': details or {}
    }
    logging.info(json.dumps(entry, ensure_ascii=False))

# === DB setup ===
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        role TEXT DEFAULT 'user'
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        name TEXT,
        category TEXT,
        price REAL,
        description TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY,
        product_id INTEGER,
        username TEXT,
        comment TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS wishlist (
        id INTEGER PRIMARY KEY,
        username TEXT,
        product_id INTEGER
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY,
        username TEXT,
        products TEXT,
        total REAL,
        date TEXT
    )''')
    # default data
    c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin','admin123','admin')")
    c.execute("INSERT OR IGNORE INTO products (name, category, price, description) VALUES ('Laptop Pro','Laptop',1299.99,'Puissant et rapide')")
    c.execute("INSERT OR IGNORE INTO products (name, category, price, description) VALUES ('Smartphone X','Phone',899.99,'Caméra 108MP')")
    c.execute("INSERT OR IGNORE INTO products (name, category, price, description) VALUES ('Wireless Mouse','Accessory',49.99,'Souris sans fil')")
    conn.commit()
    conn.close()

init_db()

# === Templates ===
BASE = """
<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<title>E-Shop Pro</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body { padding-top: 70px; background:#f8f9fa; }
.card-img-top { height:200px; object-fit:cover; }
.comment-box { margin-top:10px; }
</style>
</head><body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
<div class="container">
<a class="navbar-brand" href="/">E-Shop Pro</a>
<form class="d-flex me-auto" action="/search" method="get">
<input class="form-control me-2" type="search" name="q" placeholder="Recherche...">
<button class="btn btn-outline-light" type="submit">Search</button>
</form>
<div class="navbar-nav ms-auto">
<a class="nav-link" href="/cart">Panier</a>
{% if session.username %}
<a class="nav-link" href="/profile">{{ session.username }}</a>
<a class="nav-link" href="/logout">Déconnexion</a>
{% else %}
<a class="nav-link" href="/login">Login</a>
<a class="nav-link" href="/register">Inscription</a>
{% endif %}
<a class="nav-link" href="/upload">Upload</a>
<a class="nav-link" href="/admin">Admin</a>
</div>
</div>
</nav>
<div class="container mt-4">
{{ content|safe }}
</div>
</body></html>
"""

# === Helpers ===
def get_products(query=None, category=None):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    sql = "SELECT * FROM products WHERE 1=1"
    params = []
    if query:
        sql += " AND name LIKE ?"
        params.append('%'+query+'%')
    if category:
        sql += " AND category=?"
        params.append(category)
    c.execute(sql, params)
    products = c.fetchall()
    conn.close()
    return products

def add_to_cart(product_id):
    if 'cart' not in session: session['cart']=[]
    session['cart'].append(product_id)
    session.modified=True

def remove_from_cart(product_id):
    if 'cart' in session and product_id in session['cart']:
        session['cart'].remove(product_id)
        session.modified=True

# === Routes ===
@app.route('/')
def index():
    products = get_products()
    cards=""
    for p in products:
        cards += f'''
        <div class="col-md-4 mb-4">
        <div class="card">
        <div class="card-body">
        <h5 class="card-title">{p[1]}</h5>
        <p class="card-text">{p[4]}</p>
        <p class="h4 text-success">{p[3]} €</p>
        <a href="/product?id={p[0]}" class="btn btn-primary">Voir</a>
        <a href="/cart?add={p[0]}" class="btn btn-success">Ajouter</a>
        </div></div></div>
        '''
    content=f'<h1>Bienvenue sur E-Shop Pro</h1><div class="row">{cards}</div>'
    log_event('page_access', {'page':'home'})
    return render_template_string(BASE, content=content, session=session)

@app.route('/search')
def search():
    q=request.args.get('q','')
    products=get_products(q)
    cards=""
    for p in products:
        cards += f'''
        <div class="col-md-4 mb-4">
        <div class="card">
        <div class="card-body">
        <h5 class="card-title">{p[1]}</h5>
        <p class="card-text">{p[4]}</p>
        <p class="h4 text-success">{p[3]} €</p>
        <a href="/product?id={p[0]}" class="btn btn-primary">Voir</a>
        <a href="/cart?add={p[0]}" class="btn btn-success">Ajouter</a>
        </div></div></div>
        '''
    content = f'<h2>Résultats pour : {q}</h2><div class="row">{cards}</div>' if cards else f'<h2>Résultats pour : {q}</h2><p>Aucun résultat</p>'
    log_event('search', {'query':q})
    return render_template_string(BASE, content=content, session=session)

@app.route('/product')
def product():
    pid=request.args.get('id')
    conn=sqlite3.connect('database.db')
    c=conn.cursor()
    c.execute("SELECT * FROM products WHERE id=?",(pid,))
    p=c.fetchone()
    c.execute("SELECT * FROM comments WHERE product_id=?",(pid,))
    comments=c.fetchall()
    conn.close()
    if not p: return "Produit non trouvé",404
    comment_html=""
    for com in comments: comment_html+=f"<li><strong>{com[2]}</strong>: {com[3]}</li>"
    content=f'''
    <div class="row">
    <div class="col-md-6">
    <h1>{p[1]}</h1>
    <p>{p[4]}</p>
    <p class="h3 text-success">{p[3]} €</p>
    <a href="/cart?add={p[0]}" class="btn btn-success">Ajouter au panier</a>
    </div>
    <div class="col-md-6">
    <h3>Commentaires</h3>
    <form method="post" action="/comment">
    <input type="hidden" name="product_id" value="{p[0]}">
    <textarea name="comment" class="form-control" placeholder="Votre avis..."></textarea><br>
    <button class="btn btn-primary">Publier</button>
    </form>
    <ul class="comment-box">{comment_html}</ul>
    </div>
    </div>
    '''
    log_event('product_view',{'id':pid})
    return render_template_string(BASE, content=content, session=session)

@app.route('/comment',methods=['POST'])
def comment():
    if 'username' not in session: return redirect('/login')
    pid=request.form['product_id']
    comment_text=request.form['comment']
    conn=sqlite3.connect('database.db')
    c=conn.cursor()
    c.execute("INSERT INTO comments(product_id,username,comment) VALUES(?,?,?)",(pid,session['username'],comment_text))
    conn.commit(); conn.close()
    log_event('comment',{'product_id':pid,'comment':comment_text})
    return redirect(f'/product?id={pid}')

@app.route('/cart')
def cart():
    add_id=request.args.get('add')
    remove_id=request.args.get('remove')
    if add_id: add_to_cart(add_id); log_event('cart_add',{'product_id':add_id})
    if remove_id: remove_from_cart(remove_id); log_event('cart_remove',{'product_id':remove_id})
    items=session.get('cart',[])
    conn=sqlite3.connect('database.db')
    c=conn.cursor()
    products=[]
    total=0
    for pid in items:
        c.execute("SELECT * FROM products WHERE id=?",(pid,))
        p=c.fetchone()
        if p: products.append(p); total+=p[3]
    conn.close()
    content="<h2>Panier</h2>"
    if products:
        content+="<ul>"
        for p in products:
            content+=f"<li>{p[1]} - {p[3]} € <a href='/cart?remove={p[0]}' class='btn btn-sm btn-danger'>Supprimer</a></li>"
        content+=f"</ul><p>Total : {total} €</p><a href='/checkout' class='btn btn-success'>Payer</a>"
    else: content+="<p>Votre panier est vide.</p>"
    return render_template_string(BASE, content=content, session=session)

@app.route('/checkout',methods=['GET','POST'])
def checkout():
    if request.method=='POST':
        log_event('checkout',{'user':session.get('username')})
        items=session.get('cart',[])
        total=0
        conn=sqlite3.connect('database.db'); c=conn.cursor()
        products=[]
        for pid in items:
            c.execute("SELECT * FROM products WHERE id=?",(pid,))
            p=c.fetchone()
            if p: products.append(p[1]); total+=p[3]
        c.execute("INSERT INTO orders(username,products,total,date) VALUES(?,?,?,?)",
                  (session.get('username','guest'),','.join(products),total,datetime.utcnow().isoformat()))
        conn.commit(); conn.close()
        session['cart']=[]
        return "Paiement simulé effectué ! Merci."
    content='''
    <h2>Paiement</h2>
    <form method="post">
    <input class="form-control mb-2" placeholder="Nom sur la carte"><br>
    <input class="form-control mb-2" placeholder="Numéro carte"><br>
    <input class="form-control mb-2" placeholder="CVV"><br>
    <button class="btn btn-danger">Confirmer le paiement</button>
    </form>
    '''
    return render_template_string(BASE,content=content,session=session)

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        username=request.form['username']; password=request.form['password']
        conn=sqlite3.connect('database.db'); c=conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?",(username,password))
        user=c.fetchone(); conn.close()
        if user: session['username']=user[1]; session['role']=user[3]; log_event('login_success',{'username':username}); return redirect('/')
        else: log_event('login_failed',{'username':username}); return "Mauvais identifiants"
    content='''<h2>Connexion</h2>
    <form method="post">
    <input class="form-control mb-2" name="username" placeholder="admin"><br>
    <input class="form-control mb-2" name="password" placeholder="admin123" type="password"><br>
    <button class="btn btn-primary">Login</button>
    </form>'''
    return render_template_string(BASE,content=content,session=session)

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        username=request.form['username']; password=request.form['password']
        conn=sqlite3.connect('database.db'); c=conn.cursor()
        try: c.execute("INSERT INTO users(username,password) VALUES(?,?)",(username,password)); conn.commit(); session['username']=username
        except: return "Utilisateur existe déjà"
        finally: conn.close()
        return redirect('/')
    content='''<h2>Inscription</h2>
    <form method="post">
    <input class="form-control mb-2" name="username" placeholder="user123"><br>
    <input class="form-control mb-2" name="password" type="password" placeholder="pass123"><br>
    <button class="btn btn-success">S'inscrire</button>
    </form>'''
    return render_template_string(BASE,content=content,session=session)

@app.route('/profile')
def profile():
    if 'username' not in session: return redirect('/login')
    conn=sqlite3.connect('database.db'); c=conn.cursor()
    c.execute("SELECT * FROM orders WHERE username=?",(session['username'],))
    orders=c.fetchall(); conn.close()
    orders_html=""
    for o in orders:
        orders_html+=f"<li>Produits: {o[2]} | Total: {o[3]} € | Date: {o[Y4]}</li>"
    content=f"<h2>Profil de {session['username']}</h2><p>Rôle: {session.get('role','user')}</p>"
    content+="<h3>Commandes</h3><ul>"+orders_html+"</ul>" if orders_html else content+"<p>Aucune commande passée</p>"
    return render_template_string(BASE,content=content,session=session)

@app.route('/upload',methods=['GET','POST'])
def upload():
    if request.method=='POST':
        f=request.files['file']
        if f:
            path=os.path.join(UPLOAD_FOLDER,f.filename)
            f.save(path)
            log_event('upload',{'filename':f.filename,'size':os.path.getsize(path)})
            return f"Fichier {f.filename} uploadé ! <a href='/uploads/{f.filename}'>Voir</a>"
    content='''<h2>Upload fichier</h2>
    <form method="post" enctype="multipart/form-data">
    <input type="file" name="file"><br><br>
    <button class="btn btn-primary">Uploader</button>
    </form>'''
    return render_template_string(BASE,content=content,session=session)

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    log_event('file_access',{'file':filename})
    return send_from_directory(UPLOAD_FOLDER,filename)

@app.route('/admin')
def admin():
    if session.get('role')!='admin': return "Accès refusé"
    cmd=request.args.get('cmd')
    content="<h2>Admin Panel</h2>"
    if cmd:
        log_event('rce_attempt',{'command':cmd})
        content+=f"<p>Commande simulée: {cmd}</p>"
    content+="<p>Usage: /admin?cmd=ping 8.8.8.8</p>"
    return render_template_string(BASE,content=content,session=session)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# 404
@app.errorhandler(404)
def page_not_found(e):
    log_event('404',{ 'path':request.path })
    return render_template_string(BASE,content="<h2>Page non trouvée</h2>",session=session),404

if __name__=='__main__':
    seccomp_config.apply_seccomp_blacklist()
    print("[+] Honeypot E-commerce complet démarré sur http://0.0.0.0:5000")
    app.run(host='0.0.0.0',port=5000,threaded=True)
