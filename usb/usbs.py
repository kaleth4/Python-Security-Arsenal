import shutil
import os

def backup_folder(source, dest):
    if os.path.exists(source):
        shutil.copytree(source, dest, dirs_exist_ok=True)
        print("Backup completado.")
    else:
        print("Carpeta fuente no existe.")

# Ejemplo: Backup de Escritorio
backup_folder(r"C:\Users\TuUsuario\Desktop", r"E:\Backup\Desktop")