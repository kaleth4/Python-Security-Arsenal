@echo off
echo Herramienta USB Avanzada
echo 1. Ejecutar Antivirus
echo 2. Verificar Archivos
echo 3. Backup de Datos
set /p choice="Elige opción: "
if %choice%==1 start "Herramientas\Seguridad\malwarebytes.exe"
if %choice%==2 call verificar_archivos.bat
if %choice%==3 python backup.py