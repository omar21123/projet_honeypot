# 1. Utiliser une image Python officielle
FROM python:3.10-slim

# 2. Installer les dépendances système (pour 'seccomp' et les libs crypto)
RUN apt-get update && apt-get install -y \
    libseccomp-dev \
    gcc \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# 3. Définir le répertoire de travail dans le conteneur
WORKDIR /app

# 4. Copier et installer les dépendances Python
# On copie d'abord requirements.txt pour utiliser le cache de Docker
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 5. Copier tout le code de votre application
COPY . .

# 6. Créer le répertoire pour les données persistantes (volume)
# et donner les permissions à un utilisateur non-privilégié
RUN mkdir /app/data && chown -R www-data:www-data /app/data

# 7. Lancer l'application sous un utilisateur non-privilégié
USER www-data
CMD ["python3", "app.py"]
