
import sqlite3

def authenticate_user(username, password):
    """
    ARCHIVO VULNERABLE - SQL Injection
    Este código es vulnerable porque concatena directamente la entrada del usuario
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: concatenación directa permite inyección SQL
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"success": True, "user_id": user[0]}
    else:
        return {"success": False, "error": "Invalid credentials"}

def get_user_data(user_id):
    """Otra función vulnerable"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # También vulnerable
    query = f"SELECT * FROM user_data WHERE id = {user_id}"
    cursor.execute(query)
    
    return cursor.fetchall()
# ffdfrgtrgtrg