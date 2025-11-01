def buscar_usuario_inseguro(nombre):
    import sqlite3
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    # INSEGURO: concatenación directa permite SQL injection
    query = "SELECT * FROM usuarios WHERE nombre = '" + nombre + "'"
    cursor.execute(query)
    return cursor.fetchall()