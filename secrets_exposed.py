import sqlite3, hashlib, secrets
from pathlib import Path

DB = "mini.db"
FILES_DIR = Path("files")
FILES_DIR.mkdir(exist_ok=True)

# DB init
conn = sqlite3.connect(DB, check_same_thread=False)
conn.execute("""CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt BLOB, pwd_hash BLOB)""")
conn.commit()

# Hash seguro
def hash_pw(pw: str):
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return salt, h

def verify_pw(pw: str, salt: bytes, h: bytes):
    return secrets.compare_digest(
        hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000), h
    )

# Registro / login -> token
_sessions = {}  # token -> username (en memoria; para prod usar store persistente)
def register(u, pw):
    s, h = hash_pw(pw)
    try:
        conn.execute("INSERT INTO users(username,salt,pwd_hash) VALUES (?, ?, ?)", (u, s, h))
        conn.commit(); print("registrado")
    except Exception:
        print("usuario existe o error")

def login(u, pw):
    cur = conn.execute("SELECT salt,pwd_hash FROM users WHERE username=?", (u,))
    r = cur.fetchone()
    if r and verify_pw(pw, r[0], r[1]):
        token = secrets.token_urlsafe(32)
        _sessions[token] = u
        print("token:", token); return token
    print("credenciales invalidas"); return None

# Guardado seguro de archivo (sanitiza nombre)
def save_file(token, filename, data: bytes):
    if token not in _sessions: raise PermissionError("no autorizado")
    name = Path(filename).name  # evita path traversal
    if len(name) > 100 or ".." in name: raise ValueError("nombre inv
