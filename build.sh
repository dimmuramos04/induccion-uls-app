#!/usr/bin/env bash
# exit on error
set -o errexit

echo "1. Instalando dependencias..."
pip install -r requirements.txt

# Aplicamos migraciones completas para asegurarnos de que la base de datos esté al día
echo "2. Aplicando migraciones (Solo cambios nuevos)..."
flask db upgrade

echo "3. Verificando datos iniciales..."
# Usamos el nombre correcto de tu comando en app.py
flask init-data

echo "Build finalizado correctamente. ¡Listo para la Inducción!"