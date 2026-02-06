from app import create_app
from models import db, User, Stand, Configuracion
from werkzeug.security import generate_password_hash

app = create_app()

with app.app_context():
    # 1. Crear Stands Básicos (Necesarios para asignar Staff)
    print("Creando Stands básicos...")
    stands = [
        {'nombre': 'Mesa Central de Ayuda', 'tipo': 'servicio'},
        {'nombre': 'Entrega de Regalos - Ingeniería', 'tipo': 'entrega'},
        {'nombre': 'Biblioteca Central', 'tipo': 'servicio'},
        {'nombre': 'Bienestar Estudiantil', 'tipo': 'servicio'}
    ]

    for data in stands:
        # Verificar si existe para no duplicar
        if not Stand.query.filter_by(nombre=data['nombre']).first():
            nuevo_stand = Stand(nombre=data['nombre'], tipo=data['tipo'])
            db.session.add(nuevo_stand)
    
    db.session.commit()
    print("Stands creados.")

    # 2. Crear Configuración Inicial
    if not Configuracion.query.filter_by(clave='modo_feria_activo').first():
        db.session.add(Configuracion(clave='modo_feria_activo', valor='true'))
        db.session.add(Configuracion(clave='minimo_stands', valor='3'))
        db.session.commit()

    # 3. Crear Super Admin
    username_admin = "admin"
    password_admin = "admin123" # ¡Cámbiala después!
    
    if not User.query.filter_by(username=username_admin).first():
        print(f"Creando usuario admin: {username_admin}")
        admin = User(
            username=username_admin,
            password_hash=generate_password_hash(password_admin),
            role='admin'
            # El admin no necesita stand obligatorio
        )
        db.session.add(admin)
    else:
        print("El usuario admin ya existe.")

    # 4. Crear un Staff de Prueba (Asignado a Biblioteca)
    stand_biblio = Stand.query.filter_by(nombre='Biblioteca Central').first()
    username_staff = "staff_biblio"
    
    if not User.query.filter_by(username=username_staff).first():
        print(f"Creando usuario staff: {username_staff}")
        staff = User(
            username=username_staff,
            password_hash=generate_password_hash("staff123"),
            role='staff',
            stand_id=stand_biblio.id
        )
        db.session.add(staff)

    db.session.commit()
    print("\n¡Todo listo! Usuarios y datos base creados.")
    print(f"Admin: {username_admin} / {password_admin}")