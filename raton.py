# Generar una inyeccion sql en python
def funcion_inyeccion_sql(user_input):
    query = "SELECT * FROM users WHERE username = '" + user_input + "';"
    return query

# Ejemplo de uso
user_input = "admin' --"
print(funcion_inyeccion_sql(user_input))
