import sqlite3, hashlib, secrets, os, time
from pathlib import Path

DB = "mini_secure.db"
FILES_DIR = Path("files_secure")
FILES_DIR.mkdir(mode=0o700, exist_ok=True)

def init_db():
    created = not Path(DB).exists()
    with sqlite3.connect(DB) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt BLOB, pwd_hash BLOB)""")
        conn.execute("""CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY, username TEXT, expires INTEGER)""")
        conn.commit()
    if created:
        os.chmod(DB, 0o600)

def hash_pw(pw: str):
    salt = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode('utf-8'), salt, 200_000)
    return salt, h

def verify_pw(pw: str, salt: bytes, h: bytes):
    return secrets.compare_digest(
        hashlib.pbkdf2_hmac("sha256", pw.encode('utf-8'), salt, 200_000), h
    )

def register(u: str, pw: str) -> bool:
    if not u or not pw or len(u) > 150: 
        return False
    s, h = hash_pw(pw)
    try:
        with sqlite3.connect(DB) as conn:
            conn.execute("INSERT INTO users(username,salt,pwd_hash) VALUES (?,?,?)", (u,s,h))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

def login(u: str, pw: str):
    with sqlite3.connect(DB) as conn:
        cur = conn.execute("SELECT salt,pwd_hash FROM users WHERE username=?", (u,))
        r = cur.fetchone()
        if r and verify_pw(pw, r[0], r[1]):
            token = secrets.token_urlsafe(32)
            expires = int(time.time()) + 3600  # 1 hora
            conn.execute("INSERT INTO sessions(token,username,expires) VALUES (?,?,?)",
                         (token, u, expires))
            conn.commit()
            return token
    return None

def is_token_valid(token: str) -> bool:
    with sqlite3.connect(DB) as conn:
        cur = conn.execute("SELECT expires FROM sessions WHERE token=?", (token,))
        r = cur.fetchone()
        if not r: 
            return False
        return int(time.time()) < int(r[0])

def save_file(token: str, filename: str, data: bytes) -> bool:
    if not is_token_valid(token):
        raise PermissionError("no autorizado")
    name = Path(filename).name
    if len(name) == 0 or len(name) > 100 or ".." in name:
        raise ValueError("nombre inválido")
    target = (FILES_DIR / name).resolve()
    if not str(target).startswith(str(FILES_DIR.resolve())):
        raise ValueError("ruta inválida")
    # escribir con modo seguro: crea temporal y renombra (atomicidad simple)
    tmp = target.with_suffix(".tmp")
    with tmp.open("wb") as f:
        f.write(data)
    os.replace(tmp, target)
    os.chmod(target, 0o600)
    return True

# Inicializar
init_db()
