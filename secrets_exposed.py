def conectar_db_inseguro():
    import mysql.connector
    # INSEGURO: credenciales en código
    connection = mysql.connector.connect(
        host="localhost",
        user="admin",
        password="admin123",
        database="mydb"
    )
    return connection
