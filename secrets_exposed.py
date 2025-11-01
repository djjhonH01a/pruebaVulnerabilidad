import sqlite3, hashlib, secrets

# Crear base de datos segura
conn = sqlite3.connect("users.db")
conn.execute("""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    salt BLOB,
    password_hash BLOB
)""")
conn.commit()

# Funciones seguras
def hash_password(password: str):
    salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return salt, pwd_hash

def verify_password(password: str, salt: bytes, pwd_hash: bytes):
    new_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 200_000)
    return secrets.compare_digest(new_hash, pwd_hash)

# Registrar usuario
def register(username: str, password: str):
    salt, pwd_hash = hash_password(password)
    try:
        conn.execute("INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                     (username, salt, pwd_hash))
        conn.commit()
        print("Usuario registrado con éxito.")
    except sqlite3.IntegrityError:
        print("El usuario ya existe.")

# Iniciar sesión
def login(username: str, password: str):
    cur = conn.execute("SELECT salt, password_hash FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    if row and verify_password(password, row[0], row[1]):
        print("Login exitoso.")
    else:
        print("Credenciales incorrectas.")

# Ejemplo
register("alice", "S3guraP@ss")
login("alice", "S3guraP@ss")
