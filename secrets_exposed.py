
import os
import subprocess

def backup_user_files(username):
    """
    ARCHIVO VULNERABLE - Command Injection
    Permite ejecución de comandos arbitrarios
    """
    # VULNERABLE: concatenación directa en comando del sistema
    backup_command = "tar -czf backup.tar.gz /home/" + username + "/documents"
    os.system(backup_command)
    
    return "Backup completed for " + username

def process_log_file(filename):
    """Otra función con command injection"""
    # VULNERABLE: permite inyección de comandos
    command = ["grep", "ERROR", "/var/log/" + filename]
    result = subprocess.call(command, shell=True)
    return result
    