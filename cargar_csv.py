import csv
import os
from app import create_app, db
from models import Estudiante

app = create_app()

def cargar_datos():
    ruta_archivo = 'estudiantes.csv'
    
    if not os.path.exists(ruta_archivo):
        print(f"❌ Error: No encuentro el archivo '{ruta_archivo}'.")
        return

    with app.app_context():
        print("--- Iniciando Carga Masiva (Modo Robusto) ---")
        contador = 0
        
        # INTENTO 1: Probar con UTF-8 (Estándar moderno)
        # 'utf-8-sig' ayuda a Excel a borrar caracteres raros al inicio
        encoding_probado = 'utf-8-sig' 
        
        try:
            # Primero intentamos abrir el archivo
            f = open(ruta_archivo, 'r', encoding=encoding_probado)
            reader = csv.reader(f, delimiter=',')
            # Forzamos la lectura de la primera línea para ver si explota por encoding
            list(reader) 
            f.seek(0) # Si funciona, volvemos al inicio
        except UnicodeDecodeError:
            # INTENTO 2: Si falla, probamos con Latin-1 (Típico de Excel en Windows Chile)
            print("⚠️ Aviso: El archivo no es UTF-8. Intentando con formato Windows (Latin-1)...")
            f.close()
            encoding_probado = 'latin-1'
            f = open(ruta_archivo, 'r', encoding=encoding_probado)
            reader = csv.reader(f, delimiter=';') # A veces Excel en español usa punto y coma

        # Ahora sí procesamos
        try:
            csv_reader = csv.reader(f, delimiter=',') # Asumimos coma por defecto
            
            # Detectar si usa punto y coma (parche común en Chile)
            linea_prueba = f.readline()
            f.seek(0)
            if ';' in linea_prueba and ',' not in linea_prueba:
                 csv_reader = csv.reader(f, delimiter=';')

            next(csv_reader, None) # Saltar encabezado si existe

            for row in csv_reader:
                if len(row) < 4: continue

                # Limpieza de datos
                rut_csv = row[0].strip().replace('.', '').replace('-', '').lower() # Limpiamos RUT al cargar
                nombre_csv = row[1].strip() # Aquí ya vendrá con tilde correcta gracias al encoding
                email_csv = row[2].strip()
                carrera_csv = row[3].strip()

                if not Estudiante.query.filter_by(rut=rut_csv).first():
                    nuevo = Estudiante(
                        rut=rut_csv,
                        nombre=nombre_csv,
                        email=email_csv,
                        carrera=carrera_csv
                    )
                    db.session.add(nuevo)
                    contador += 1
            
            db.session.commit()
            print(f"🎉 Éxito: Se cargaron {contador} estudiantes usando formato {encoding_probado}.")
            
        except Exception as e:
            print(f"❌ Error procesando datos: {e}")
        finally:
            f.close()

if __name__ == '__main__':
    cargar_datos()