
# ARCHIVO VULNERABLE - Secretos expuestos

# Credenciales hardcodeadas
DATABASE_PASSWORD = "admin123"
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
SECRET_KEY = "mi-clave-super-secreta-2024"

# Configuración de base de datos con credenciales
DATABASE_CONFIG = {
    "host": "localhost",
    "username": "root",
    "password": "password123",  # Password expuesta
    "database": "production_db"
}

def connect_to_api():
    """Función que expone API key"""
    import requests
    
    headers = {
        "Authorization": "Bearer sk-1234567890abcdefghijklmnopqrstuvwxyz",
        "Content-Type": "application/json"
    }
    
    response = requests.get("https://api.example.com/data", headers=headers)
    return response.json()

def connect_database():
    """Conexión con credenciales hardcodeadas"""
    import mysql.connector
    
    connection = mysql.connector.connect(
        host='localhost',
        user='admin',
        password='admin123',  # Otra password expuesta
        database='users'
    )
    
    return connection

# Token de GitHub expuesto
GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz123456"
# eferfeergergerg