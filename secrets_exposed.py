
import sqlite3
import os
import subprocess

def authenticate_user_secure(username, password):
    """
    ARCHIVO SEGURO - Uso correcto de consultas parametrizadas
    """
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SEGURO: consulta parametrizada
    query = "SELECT * FROM users WHERE username=? AND password=?"
    cursor.execute(query, (username, password))
    
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"success": True, "user_id": user[0]}
    else:
        return {"success": False, "error": "Invalid credentials"}

def validate_user_input(input_string):
    """Función con validación apropiada"""
    # Validar entrada
    if not input_string or len(input_string) > 100:
        raise ValueError("Invalid input length")
    
    # Sanitizar caracteres peligrosos
    allowed_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    if not all(c in allowed_chars for c in input_string):
        raise ValueError("Invalid characters in input")
    
    return input_string

def calculate_total(items):
    """Función matemática simple y segura"""
    if not isinstance(items, list):
        return 0
    
    total = 0
    for item in items:
        if isinstance(item, (int, float)) and item >= 0:
            total += item
    
    return total
    