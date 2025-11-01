def ejecutar_comando_inseguro(filename):
    import os
    # INSEGURO: permite inyección de comandos
    os.system("cat " + filename)