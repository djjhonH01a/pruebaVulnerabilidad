
import os

def read_user_file(filename):
    """
    ARCHIVO VULNERABLE - Path Traversal
    Permite acceso a archivos fuera del directorio permitido
    """
    # VULNERABLE: no valida la ruta del archivo
    file_path = "/var/www/uploads/" + filename
    
    try:
        with open(file_path, 'r') as file:
            return file.read()
    except Exception as e:
        return f"Error: {e}"

def save_user_upload(filename, content):
    """Función vulnerable a directory traversal"""
    # VULNERABLE: permite escribir en cualquier ubicación
    save_path = "./uploads/" + filename
    
    with open(save_path, 'w') as file:
        file.write(content)
    
    return f"File saved: {save_path}"

def include_template(template_name):
    """Función que permite inclusión de archivos arbitrarios"""
    # VULNERABLE: permite ../../../etc/passwd
    template_path = "./templates/" + template_name
    
    with open(template_path, 'r') as template:
        return template.read()




# Ejemplos de uso