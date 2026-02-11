import os
import click
import sentry_sdk
import pytz
from sentry_sdk.integrations.flask import FlaskIntegration
from flask import Flask
from flask_migrate import Migrate
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_cors import CORS
from flask_socketio import SocketIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash
from dotenv import load_dotenv
from models import db, User, Stand, Configuracion, Visita, Estudiante, Encuesta, Bloque, socketio

# 1. Cargar variables
load_dotenv()

# 2. Inicializar extensiones (Solo las que no están en models)
migrate = Migrate()
login_manager = LoginManager()

# Configuración Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri="memory://"
)

def create_app():
    # Configuración Sentry
    if os.getenv('SENTRY_DSN'):
        sentry_sdk.init(
            dsn=os.getenv('SENTRY_DSN'),
            integrations=[FlaskIntegration()],
            traces_sample_rate=1.0, 
            profiles_sample_rate=1.0,
            send_default_pii=True
        )

    app = Flask(__name__)

    # Configuración App
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev_key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Inicializar Extensions con la app
    db.init_app(app) 
    migrate.init_app(app, db)
    csrf = CSRFProtect(app)
    login_manager.init_app(app)
    socketio.init_app(app, cors_allowed_origins="*")
    CORS(app)

    # Configuración Rate Limiting
    limiter.init_app(app)

    # Configuración Login
    login_manager.login_view = 'login'
    login_manager.login_message_category = "warning"

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- COMANDO PARA INICIALIZAR DATOS ---
    @app.cli.command("init-data")
    def init_data():
        """Crea tablas y usuario admin desde .env"""
        click.echo("Iniciando configuración inicial...")
        
        # 1. Crear tablas si no existen
        with app.app_context():
            db.create_all()
        
            # 2. Crear Configuración Base
            if not Configuracion.query.filter_by(clave='modo_feria_activo').first():
                db.session.add(Configuracion(clave='modo_feria_activo', valor='true'))
                db.session.add(Configuracion(clave='minimo_stands', valor='3'))
                click.echo("- Configuración creada.")

            # 3. Crear Stands por defecto
            stands_nombres = ['Mesa Ayuda', 'Entrega Regalos', 'Biblioteca', 'Bienestar']
            for nombre in stands_nombres:
                if not Stand.query.filter_by(nombre=nombre).first():
                    tipo = 'entrega' if 'Regalos' in nombre else 'servicio'
                    db.session.add(Stand(nombre=nombre, tipo=tipo))
            click.echo("- Stands creados.")

            # 4. Crear Admin Seguro
            admin_user = os.getenv('ADMIN_USERNAME')
            admin_pass = os.getenv('ADMIN_PASSWORD')
            
            if not User.query.filter_by(username=admin_user).first():
                new_admin = User(
                    username=admin_user,
                    password_hash=generate_password_hash(admin_pass),
                    role='admin'
                )
                db.session.add(new_admin)
                click.echo(f"- Usuario Admin creado: {admin_user}")
            else:
                click.echo("- El usuario Admin ya existe.")

            # 5. Crear STAFF DE PRUEBA (Desde .env)
            staff_user = os.getenv('STAFF_USERNAME')
            staff_pass = os.getenv('STAFF_PASSWORD')
            
            if not User.query.filter_by(username=staff_user).first():
                # Buscar el stand al que pertenecerá (Biblioteca por defecto para pruebas)
                stand_biblio = Stand.query.filter_by(nombre='Biblioteca').first()
                
                new_staff = User(
                    username=staff_user,
                    password_hash=generate_password_hash(staff_pass),
                    role='staff',
                    stand_id=stand_biblio.id if stand_biblio else None
                )
                db.session.add(new_staff)
                click.echo(f"- Usuario Staff creado: {staff_user}")
            else:
                click.echo("- El usuario Staff ya existe.")
            
            db.session.commit()
            click.echo("¡Sistema listo para usar!")


    # Registrar Rutas (Contexto de Aplicación)
    with app.app_context():
        import routes

    @app.template_filter('fecha_chile')
    def fecha_chile_filter(fecha_utc):
        if not fecha_utc:
            return "-"
        # Si la fecha no tiene zona horaria, asumimos UTC
        if fecha_utc.tzinfo is None:
            fecha_utc = pytz.utc.localize(fecha_utc)
        
        # Convertir a Santiago
        tz_cl = pytz.timezone('America/Santiago')
        fecha_cl = fecha_utc.astimezone(tz_cl)
        
        # Formato bonito: "05-02 18:30"
        return fecha_cl.strftime('%d-%m %H:%M')
    
    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True, port=5002)