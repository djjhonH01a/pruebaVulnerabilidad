import sqlite3
import hashlib
import secrets
import os
from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from markupsafe import escape
from functools import wraps
import re

app = Flask(__name__)
# Clave secreta generada aleatoriamente (en producción usar variable de entorno)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Rate limiting para prevenir ataques de fuerza bruta
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Configuración segura de archivos
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Conexión segura a base de datos
def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# Inicializar base de datos
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Usuario de prueba con contraseña hasheada
    hashed = generate_password_hash('SecurePass123!', method='pbkdf2:sha256')
    try:
        cursor.execute(
            "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
            ('admin', hashed, 'admin')
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # Usuario ya existe
    conn.close()

# Decorador para requerir autenticación
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({"error": "Autenticación requerida"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Validación de contraseña fuerte
def validate_password(password):
    if len(password) < 8:
        return False, "La contraseña debe tener al menos 8 caracteres"
    if not re.search(r'[A-Z]', password):
        return False, "Debe contener al menos una mayúscula"
    if not re.search(r'[a-z]', password):
        return False, "Debe contener al menos una minúscula"
    if not re.search(r'\d', password):
        return False, "Debe contener al menos un número"
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Debe contener al menos un carácter especial"
    return True, "Contraseña válida"

# Validación de nombre de usuario
def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False, "El nombre debe tener entre 3 y 20 caracteres"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Solo se permiten letras, números y guiones bajos"
    return True, "Usuario válido"

# Login endpoint con protección
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # Máximo 5 intentos por minuto
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({"error": "Usuario y contraseña requeridos"}), 400
        
        # Consulta parametrizada para prevenir SQL Injection
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password, role FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()
        conn.close()
        
        # Verificación segura de contraseña con hash
        if user and check_password_hash(user['password'], password):
            # Crear sesión segura
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session.permanent = False  # Sesión temporal
            
            return jsonify({
                "success": True,
                "message": f"Bienvenido {user['username']}",
                "role": user['role']
            }), 200
        else:
            # Mensaje genérico para no revelar si el usuario existe
            return jsonify({"error": "Credenciales inválidas"}), 401
            
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Búsqueda de usuarios con sanitización
@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '').strip()
    
    # Sanitización para prevenir XSS
    safe_query = escape(query)
    
    # Limitar longitud de búsqueda
    if len(query) > 100:
        return jsonify({"error": "Búsqueda demasiado larga"}), 400
    
    return jsonify({
        "results": f"Resultados para: {safe_query}",
        "query": safe_query
    }), 200

# Cambiar contraseña con validación
@app.route('/change_password', methods=['POST'])
@login_required
@limiter.limit("3 per hour")
def change_password():
    try:
        data = request.get_json()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        
        # Verificar que el usuario esté cambiando su propia contraseña
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        
        # Verificar contraseña actual
        if not user or not check_password_hash(user['password'], current_password):
            conn.close()
            return jsonify({"error": "Contraseña actual incorrecta"}), 401
        
        # Validar nueva contraseña
        is_valid, message = validate_password(new_password)
        if not is_valid:
            conn.close()
            return jsonify({"error": message}), 400
        
        # Actualizar con hash seguro
        hashed = generate_password_hash(new_password, method='pbkdf2:sha256')
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({"success": True, "message": "Contraseña actualizada"}), 200
        
    except Exception as e:
        app.logger.error(f"Error al cambiar contraseña: {str(e)}")
        return jsonify({"error": "Error interno del servidor"}), 500

# Validar extensión de archivo
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Subir archivo con validación
@app.route('/upload', methods=['POST'])
@login_required
@limiter.limit("10 per hour")
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "No se encontró archivo"}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({"error": "Nombre de archivo vacío"}), 400
        
        # Validar extensión
        if not allowed_file(file.filename):
            return jsonify({"error": "Tipo de archivo no permitido"}), 400
        
        # Validar tamaño
        file.seek(0, os.SEEK_END)
        size = file.tell()
        file.seek(0)
        
        if size > MAX_FILE_SIZE:
            return jsonify({"error": "Archivo demasiado grande (máx 5MB)"}), 400
        
        # Nombre seguro para prevenir Path Traversal
        filename = secure_filename(file.filename)
        
        # Agregar timestamp para evitar sobrescritura
        name, ext = os.path.splitext(filename)
        safe_filename = f"{name}_{secrets.token_hex(8)}{ext}"
        
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
        file.save(filepath)
        
        return jsonify({
            "success": True,
            "message": "Archivo subido correctamente",
            "filename": safe_filename
        }), 200
        
    except Exception as e:
        app.logger.error(f"Error al subir archivo: {str(e)}")
        return jsonify({"error": "Error al procesar archivo"}), 500

# Ver archivo con validación
@app.route('/view_file')
@login_required
def view_file():
    try:
        filename = request.args.get('file', '')
        
        if not filename:
            return jsonify({"error": "Nombre de archivo requerido"}), 400
        
        # Validar y sanitizar nombre de archivo
        safe_filename = secure_filename(filename)
        filepath = os.path.join(UPLOAD_FOLDER, safe_filename)
        
        # Verificar que el archivo está dentro del directorio permitido
        if not os.path.abspath(filepath).startswith(os.path.abspath(UPLOAD_FOLDER)):
            return jsonify({"error": "Acceso denegado"}), 403
        
        # Verificar que el archivo existe
        if not os.path.exists(filepath):
            return jsonify({"error": "Archivo no encontrado"}), 404
        
        # Leer solo archivos de texto
        if not allowed_file(safe_filename):
            return jsonify({"error": "Tipo de archivo no permitido"}), 400
        
        with open(filepath, 'r') as f:
            content = f.read(10000)  # Limitar lectura a 10KB
        
        return jsonify({"content": content}), 200
        
    except Exception as e:
        app.logger.error(f"Error al leer archivo: {str(e)}")
        return jsonify({"error": "Error al leer archivo"}), 500

# API con autenticación por token
@app.route('/api/data')
@limiter.limit("100 per hour")
def api_data():
    # Token debe venir de variable de entorno
    valid_token = os.environ.get('API_TOKEN')
    
    if not valid_token:
        return jsonify({"error": "API no configurada"}), 500
    
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header.startswith('Bearer '):
        return jsonify({"error": "Formato de autorización inválido"}), 401
    
    token = auth_header.replace('Bearer ', '')
    
    # Comparación segura para prevenir timing attacks
    if secrets.compare_digest(token, valid_token):
        return jsonify({"data": "información sensible"}), 200
    
    return jsonify({"error": "No autorizado"}), 401

# Logout
@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Sesión cerrada"}), 200

# Manejo de errores
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"Error 500: {str(e)}")
    return jsonify({"error": "Error interno del servidor"}), 500

if __name__ == '__main__':
    init_db()
    # NO usar debug=True en producción
    # Configurar con variables de entorno
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(
        debug=debug_mode,
        host='127.0.0.1',  # Solo localhost, no 0.0.0.0
        port=5000
    )