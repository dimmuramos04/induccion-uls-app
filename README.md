# 🎓 Sistema de Gestión - Feria de Inducción ULS

Aplicación web integral desarrollada para gestionar el flujo de estudiantes, validación de visitas, entrega de regalos y sorteos en tiempo real durante la Feria de Inducción Universitaria.

## 🚀 Características Principales

### 🛡️ Roles y Seguridad
* **Administrador:** Panel de control total, gestión de usuarios (Staff), carga masiva de estudiantes (CSV) y reportes de auditoría.
* **Staff:** Escaneo de códigos QR para validar visitas en stands y entrega de kits de bienvenida.
* **Animador:** Interfaz exclusiva para controlar el sorteo en pantalla gigante desde un dispositivo móvil.

### 📊 Funcionalidades Clave
* **Validación QR:** Registro de visitas por stand con detección de duplicados.
* **Auditoría Forense:** Registro exacto de *quién* (Staff) y *cuándo* (Hora Chile) realizó cada escaneo o entrega.
* **Sorteo en Tiempo Real:** Sistema de tómbola digital con WebSockets (SocketIO), animación tragamonedas y sonido. Garantiza que un alumno no gane dos veces.
* **Reportes:** Exportación de Excel maestro con trazabilidad completa y estadísticas de avance por carrera.

## 🛠️ Tecnologías Utilizadas

* **Backend:** Python 3.12, Flask.
* **Base de Datos:** PostgreSQL (SQLAlchemy ORM).
* **Tiempo Real:** Flask-SocketIO (Eventlet).
* **Frontend:** HTML5, Bootstrap 5, Jinja2, JavaScript.
* **Despliegue:** Gunicorn, Render, Psycogreen.

---

## 💻 Instalación Local (Desarrollo)

Sigue estos pasos para correr el proyecto en tu máquina:

1.  **Clonar el repositorio:**
    ```bash
    git clone [https://github.com/dimmuramos04/induccion-uls-app.git](https://github.com/dimmuramos04/induccion-uls-app.git)
    cd induccion-uls-app
    ```

2.  **Crear entorno virtual:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # En Windows: venv\Scripts\activate
    ```

3.  **Instalar dependencias:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configurar Variables de Entorno (.env):**
    Crea un archivo `.env` en la raíz y agrega:
    ```env
    SECRET_KEY=tu_clave_secreta_aqui
    DATABASE_URL=sqlite:///site.db  # O tu URL de Postgres local
    FLASK_APP=app.py
    FLASK_DEBUG=1
    ```

5.  **Inicializar Base de Datos:**
    ```bash
    flask db upgrade
    flask init-data  # Crea usuario admin y datos base
    ```

6.  **Ejecutar:**
    ```bash
    flask run
    ```

---

## ☁️ Despliegue en Render

Esta aplicación está optimizada para desplegarse en [Render](https://render.com).

### Configuración del Web Service:

1.  **Build Command:** `./build.sh`
2.  **Start Command:** `gunicorn --worker-class eventlet -w 1 wsgi:app`
3.  **Environment Variables:**
    * `DATABASE_URL`: (Internal URL de tu base de datos Postgres en Render).
    * `SECRET_KEY`: (Genera una clave segura).
    * `FLASK_APP`: `app.py`

### Archivos clave para producción:
* `wsgi.py`: Punto de entrada para Gunicorn usando Eventlet (necesario para WebSockets).
* `build.sh`: Script seguro que instala dependencias y ejecuta migraciones sin borrar datos existentes.

---

## 📄 Licencia

Desarrollado para la Unidad de Inducción - Universidad de La Serena.