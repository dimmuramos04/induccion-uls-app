from flask import request, render_template, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timedelta
from functools import wraps 
from forms import LoginForm
import pytz
import io
import csv
from flask import Response
from flask import request, redirect, url_for, flash
from flask import make_response
from flask_socketio import emit
import random
from flask import current_app as app 
from app import db, limiter
from models import User, Estudiante, Stand, Visita, Configuracion, socketio
from sqlalchemy import func, case
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload


# Cache global en memoria
_config_cache = {}
_config_cache_ttl = {}

def get_config_cached(clave, default=None, ttl_seconds=30):
    """
    Obtiene un valor de configuración con cache inteligente.
    
    Args:
        clave: Nombre de la configuración (ej: 'minimo_stands')
        default: Valor por defecto si no existe
        ttl_seconds: Tiempo de vida del cache en segundos (default: 30)
    
    Returns:
        El valor de la configuración
    
    Ejemplo:
        minimo = get_config_cached('minimo_stands', '3', ttl_seconds=60)
    """
    now = datetime.utcnow()
    
    # Verificar si está en cache y no ha expirado
    if clave in _config_cache:
        expira_en = _config_cache_ttl.get(clave)
        if expira_en and now < expira_en:
            # Cache válido, devolver valor
            return _config_cache[clave]
    
    # Cache expirado o no existe, buscar en BD
    valor = Configuracion.get_valor(clave, default)
    
    # Guardar en cache con tiempo de expiración
    _config_cache[clave] = valor
    _config_cache_ttl[clave] = now + timedelta(seconds=ttl_seconds)
    
    return valor


def invalidar_cache_config(clave=None):
    """
    Invalida el cache de configuración.
    
    Args:
        clave: Si se especifica, solo invalida esa clave.
               Si es None, invalida todo el cache.
    
    Ejemplo:
        # Invalidar solo 'minimo_stands'
        invalidar_cache_config('minimo_stands')
        
        # Invalidar todo
        invalidar_cache_config()
    """
    if clave:
        # Invalidar solo una clave específica
        _config_cache.pop(clave, None)
        _config_cache_ttl.pop(clave, None)
    else:
        # Invalidar todo el cache
        _config_cache.clear()
        _config_cache_ttl.clear()

# --- RUTAS DE AUTENTICACIÓN ---

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("100 per minute")  
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif current_user.role == 'animador':
            return redirect(url_for('animador_dashboard'))
        else:
            return redirect(url_for('staff_dashboard'))

    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            # Verificar si debe cambiar contraseña
            if user.must_change_password:
                flash('⚠️ Por seguridad, debes cambiar tu contraseña inicial.', 'warning')
                return redirect(url_for('cambiar_password'))
            
            flash(f'Bienvenido, {user.username}!', 'success')
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'animador': 
                return redirect(url_for('animador_dashboard'))
            else:
                return redirect(url_for('staff_dashboard'))
        else:
            flash('Usuario o contraseña incorrectos', 'danger')
            
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Has cerrado sesión.', 'info')
    return redirect(url_for('login'))

# --- PANELES (DASHBOARDS) ---

@app.route('/admin')
@login_required
def admin_dashboard():
    # 1. Seguridad: Solo admin entra aquí
    if current_user.role != 'admin':
        flash('Acceso denegado. Zona de Administradores.', 'warning')
        return redirect(url_for('login'))
    
    # 2. Calcular Estadísticas
    total_estudiantes = Estudiante.query.count()
    regalos_entregados = Estudiante.query.filter_by(tiene_regalo=True).count()
    
    # Calcular porcentaje para la barra de progreso (evitando división por cero)
    avance_regalos = 0
    if total_estudiantes > 0:
        avance_regalos = int((regalos_entregados / total_estudiantes) * 100)
        
    # 3. Obtener los últimos 10 movimientos (Visitas y Entregas)
    # Nota: Aquí traemos las visitas más recientes ordenadas por fecha
    ultimos_movimientos = Visita.query.order_by(Visita.timestamp.desc()).limit(10).all()
    # Obtener configuración actual para mostrarla en el input (Usamos 'minimo_stands' de app.py)
    min_visitas_actual = Configuracion.get_valor('minimo_stands', '3')

    # 4. Obtener lista de stands para posibles futuras funcionalidades
    lista_stands = Stand.query.all()
    lista_staff = User.query.filter_by(role='staff').all()
    lista_animadores = User.query.filter_by(role='animador').all()
    
    return render_template('admin_dashboard.html', 
                           total=total_estudiantes,
                           entregados=regalos_entregados,
                           avance=avance_regalos,
                           movimientos=ultimos_movimientos,
                           min_visitas=min_visitas_actual,
                           stands=lista_stands,
                           lista_staff=lista_staff,
                           lista_animadores=lista_animadores)

@app.route('/staff')
@login_required
def staff_dashboard():
    if current_user.role != 'staff':
        flash('Acceso denegado. Zona de Staff.', 'warning')
        return redirect(url_for('login'))
    return render_template('staff_dashboard.html')

@app.route('/animador_dashboard')
@login_required
def animador_dashboard():
    if current_user.role not in ['animador', 'admin']: 
        flash('Acceso exclusivo para animadores.', 'danger')
        return redirect(url_for('login'))
    
    # 2. Obtener las carreras activas (definidas por el Admin)
    carreras_str = Configuracion.get_valor('sorteo_carreras_en_juego', '')
    lista_carreras = carreras_str.split(',') if carreras_str else []
    
    # 3. Enviar esa lista al HTML
    return render_template('animador_dashboard.html', carreras=lista_carreras)

# --- API PARA EL ESCÁNER Y VALIDACIÓN  ---

@app.route('/scan', methods=['POST']) 
@login_required 
def scan_qr():
    # 1. Recibir datos del Javascript
    data = request.get_json()
    rut_leido = data.get('rut')

    print(f"📷 SCAN: Staff {current_user.username} escaneó RUT: {rut_leido}")
    
    if not rut_leido:
        return jsonify({'status': 'error', 'message': 'No se recibió datos'}), 400

    # 2. Validar que el staff tenga stand asignado
    if not current_user.stand_asignado:
        return jsonify({
            'status': 'error',
            'message': 'Error de configuración: Usuario sin stand asignado. Contacta al administrador.'
        }), 500
    
    # 3. Buscar al estudiante (Limpieza básica de RUT)
    rut_limpio = rut_leido.replace('.', '').replace('-', '').lower()
    estudiante = Estudiante.query.filter_by(rut=rut_limpio).first()

    if not estudiante:
        print(f"❌ SCAN: RUT {rut_limpio} NO encontrado en BD")
        return jsonify({'status': 'error', 'message': 'Estudiante no encontrado en base de datos'}), 404

    print(f"✅ SCAN: Encontrado ID={estudiante.id}, Nombre={estudiante.nombre}")
    # 4. Lógica según el tipo de Stand
    tipo_stand = current_user.stand_asignado.tipo
    mensaje = ""
    estado = "success"
    
    # CASO A: Entrega de Regalos
    if tipo_stand == 'entrega':
        if estudiante.tiene_regalo:
            print(f"⚠️ SCAN: ID={estudiante.id} ya tiene regalo")
            nombre_staff = estudiante.staff_regalo.username if estudiante.staff_regalo else "Desconocido"
            return jsonify({
                'status': 'warning',
                'estudiante': {'nombre': estudiante.nombre, 'carrera': estudiante.carrera},
                'message': f'¡ALERTA! Regalo ya entregado por {nombre_staff} el {estudiante.fecha_entrega.strftime("%d/%m %H:%M")}'
            })
        
        # Usamos la configuración centralizada. Default 3 si no existe.
        minimo_requerido = int(get_config_cached('minimo_stands', '3', ttl_seconds=30))
        visitas_actuales = Visita.query.filter_by(estudiante_id=estudiante.id).count()

        if visitas_actuales < minimo_requerido:
            faltan = minimo_requerido - visitas_actuales
            return jsonify({
                'status': 'warning',
                'estudiante': {'nombre': estudiante.nombre, 'carrera': estudiante.carrera},
                'message': f'⛔ INCOMPLETO: Ha visitado {visitas_actuales} de {minimo_requerido} stands. Le faltan {faltan}.'
            })
        
        try:
            rows_affected = db.session.query(Estudiante).filter(
                Estudiante.id == estudiante.id,
                Estudiante.tiene_regalo == False  # Solo si NO tiene regalo
            ).update({
                'tiene_regalo': True,
                'fecha_entrega': datetime.now(pytz.utc),
                'staff_regalo_id': current_user.id,
                'fecha_entrega_regalo': datetime.now(pytz.utc)
            }, synchronize_session=False)
            
            db.session.commit()
            
            if rows_affected == 0:
                # Otro staff ya entregó el regalo simultáneamente
                db.session.rollback()
                estudiante = Estudiante.query.get(estudiante.id)  # Recargar datos
                nombre_staff = estudiante.staff_regalo.username if estudiante.staff_regalo else "Desconocido"
                return jsonify({
                    'status': 'warning',
                    'estudiante': {'nombre': estudiante.nombre, 'carrera': estudiante.carrera},
                    'message': f'¡ALERTA! Regalo ya entregado por {nombre_staff} el {estudiante.fecha_entrega.strftime("%d/%m %H:%M")}'
                })
            
            mensaje = "¡Entrega registrada exitosamente!"
            
        except Exception as e:
            db.session.rollback()
            print(f"Error en entrega de regalo: {e}")
            return jsonify({
                'status': 'error',
                'message': 'Error al registrar la entrega. Intenta nuevamente.'
            }), 500

    # CASO B: Servicio / Bienestar (Solo registra visita)
    elif tipo_stand == 'servicio':
        # ✅ FIX: Manejo de IntegrityError para duplicados
        try:
            nueva_visita = Visita(
                estudiante_id=estudiante.id, 
                stand_id=current_user.stand_asignado.id, 
                staff_id=current_user.id,
                timestamp=datetime.now(pytz.utc)
            )
            db.session.add(nueva_visita)
            db.session.commit()
            mensaje = "Visita registrada correctamente."
            
        except IntegrityError:
            # Ya existe una visita de este estudiante en este stand
            db.session.rollback()
            mensaje = "El estudiante ya visitó este stand previamente."
            estado = "warning"
            
        except Exception as e:
            db.session.rollback()
            print(f"Error en registro de visita: {e}")
            return jsonify({
                'status': 'error',
                'message': 'Error al registrar la visita. Intenta nuevamente.'
            }), 500

    return jsonify({
        'status': estado,
        'estudiante': {
            'nombre': estudiante.nombre, 
            'carrera': estudiante.carrera,
        },
        'message': mensaje
    })

# --- GESTIÓN DE ESTUDIANTES (ADMIN) ---

@app.route('/admin/agregar_manual', methods=['POST'])
@login_required
def agregar_estudiante_manual():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    # Recibir datos del formulario
    rut = request.form.get('rut').strip().replace('.', '').replace('-', '').lower()
    nombre = request.form.get('nombre').strip()
    carrera = request.form.get('carrera').strip()
    email = request.form.get('email', '').strip()

    # Validar si ya existe
    if Estudiante.query.filter_by(rut=rut).first():
        flash(f'Error: El RUT {rut} ya existe en el sistema.', 'danger')
    else:
        nuevo = Estudiante(rut=rut, nombre=nombre, carrera=carrera, email=email)
        db.session.add(nuevo)
        db.session.commit()
        flash(f'¡Estudiante {nombre} agregado correctamente!', 'success')

    return redirect(url_for('admin_dashboard'))

# --- CARGA MASIVA DESDE CSV (ADMIN) ---
@app.route('/admin/cargar_csv', methods=['POST'])
@login_required
def cargar_csv_web():
    if current_user.role != 'admin':
        return redirect(url_for('login'))

    # Verificar si se subió archivo
    if 'archivo_csv' not in request.files:
        flash('No se seleccionó ningún archivo.', 'warning')
        return redirect(url_for('admin_dashboard'))

    archivo = request.files['archivo_csv']
    if archivo.filename == '':
        flash('El archivo no tiene nombre.', 'warning')
        return redirect(url_for('admin_dashboard'))

    if archivo:
        try:
            # 1. Leer el archivo en binario (bytes) primero
            file_bytes = archivo.read()

            # 2. INTENTO DE DECODIFICACIÓN (La parte inteligente)
            try:
                # Intentamos UTF-8 (Estándar moderno)
                contenido_texto = file_bytes.decode('utf-8')
            except UnicodeDecodeError:
                # Si falla, usamos Latin-1 (Excel Windows)
                contenido_texto = file_bytes.decode('latin-1')

            # 3. Convertir a Stream para que CSV lo lea
            stream = io.StringIO(contenido_texto, newline=None)
            csv_reader = csv.reader(stream)
            
            # Detectar si usa punto y coma (;) en vez de coma
            # Leemos la primera línea para "olfatear" el formato
            primer_linea = stream.readline() 
            stream.seek(0) # Volvemos al principio

            if ';' in primer_linea and ',' not in primer_linea:
                csv_reader = csv.reader(stream, delimiter=';')
            else:
                csv_reader = csv.reader(stream, delimiter=',')

            # Saltar encabezado (Asumimos que siempre hay título)
            next(csv_reader, None) 

            contador_nuevos = 0
            contador_repetidos = 0
            errores = 0

            for row in csv_reader:
                try:
                    if len(row) >= 4: # Rut, Nombre, Email, Carrera
                        rut_csv = row[0].strip().replace('.', '').replace('-', '').lower()
                        
                        # VERIFICACIÓN DE DUPLICADOS
                        if not Estudiante.query.filter_by(rut=rut_csv).first():
                            nuevo = Estudiante(
                                rut=rut_csv,
                                nombre=row[1].strip(),
                                email=row[2].strip(),
                                carrera=row[3].strip()
                            )
                            db.session.add(nuevo)
                            contador_nuevos += 1
                        else:
                            contador_repetidos += 1 # Contamos los que ya estaban
                except Exception:
                    errores += 1
                    continue

            db.session.commit()
            
            # Mensaje con detalle
            if contador_nuevos > 0:
                flash(f'✅ Éxito: {contador_nuevos} estudiantes nuevos cargados. ({contador_repetidos} ya existían)', 'success')
            else:
                flash(f'⚠️ No se agregaron nuevos: {contador_repetidos} estudiantes ya existían en la base de datos.', 'warning')

        except Exception as e:
            flash(f'Error crítico al procesar el archivo: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))

# --- CONFIGURACIÓN DEL EVENTO (ADMIN) ---
@app.route('/admin/configurar', methods=['POST'])
@login_required
def configurar_evento():
    if current_user.role != 'admin':
        return redirect(url_for('login'))
    
    nuevo_minimo = request.form.get('min_visitas')
    
    # Usamos el método helper de Configuracion para guardar
    Configuracion.set_valor('minimo_stands', nuevo_minimo)
    invalidar_cache_config('minimo_stands') # Invalida el cache para que se actualice en tiempo real
    
    flash(f'Configuración actualizada: Se requieren {nuevo_minimo} visitas para el regalo.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- RUTAS DE GESTIÓN AVANZADA (ADMIN) ---
@app.route('/admin/cache_status')
@login_required
def cache_status():
    """Solo para admins, ver el estado del cache"""
    if current_user.role != 'admin': 
        return redirect(url_for('login'))
    
    now = datetime.utcnow()
    status = {}
    
    for clave, valor in _config_cache.items():
        expira_en = _config_cache_ttl.get(clave)
        segundos_restantes = (expira_en - now).total_seconds() if expira_en else 0
        
        status[clave] = {
            'valor': valor,
            'expira_en': f"{segundos_restantes:.0f} segundos",
            'estado': 'Válido' if segundos_restantes > 0 else 'Expirado'
        }
    
    return jsonify(status)

# --- GESTIÓN: CREAR STAND ---
@app.route('/admin/crear_stand', methods=['POST'])
@login_required
def crear_stand():
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    nombre = request.form.get('nombre')
    tipo = request.form.get('tipo') # 'servicio' o 'entrega'
    icono = request.form.get('icono')
    
    nuevo_stand = Stand(nombre=nombre, tipo=tipo, icono=icono)
    db.session.add(nuevo_stand)
    db.session.commit()
    
    flash(f'Stand "{nombre}" creado exitosamente.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN: EDITAR STAND ---
@app.route('/admin/editar_stand/<int:id>', methods=['POST'])
@login_required
def editar_stand(id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    stand = Stand.query.get_or_404(id)
    
    # Actualizamos datos
    stand.nombre = request.form.get('nombre')
    stand.tipo = request.form.get('tipo')
    stand.icono = request.form.get('icono')
    
    db.session.commit()
    flash(f'Stand "{stand.nombre}" actualizado correctamente.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN: CREAR ANIMADOR ---
@app.route('/admin/crear_animador', methods=['POST'])
@login_required
def crear_animador():
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Validar que no exista
    if User.query.filter_by(username=username).first():
        flash('⚠️ Ese nombre de usuario ya existe.', 'warning')
        return redirect(url_for('admin_dashboard'))
    
    # Crear usuario con rol 'animador' y SIN stand
    nuevo_animador = User(
        username=username, 
        password_hash=generate_password_hash(password),
        role='animador',
        stand_id=None,
        must_change_password=True
    )
    
    db.session.add(nuevo_animador)
    db.session.commit()
    
    flash(f'🎤 Animador "{username}" creado exitosamente.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN: CREAR STAFF ---
@app.route('/admin/crear_staff', methods=['POST'])
@login_required
def crear_staff():
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    stand_id = request.form.get('stand_id')
    
    # Validar que usuario no exista
    if User.query.filter_by(username=username).first():
        flash('El nombre de usuario ya existe.', 'danger')
        return redirect(url_for('admin_dashboard'))
        
    nuevo_staff = User(
        username=username,
        password_hash=generate_password_hash(password),
        role='staff',
        stand_id=stand_id,
        must_change_password=True
    )
    db.session.add(nuevo_staff)
    db.session.commit()
    
    flash(f'Usuario staff "{username}" creado y asignado.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN: EDITAR STAFF ---
@app.route('/admin/editar_staff/<int:id>', methods=['POST'])
@login_required
def editar_staff(id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    usuario = User.query.get_or_404(id)
    username = request.form.get('username')
    password = request.form.get('password') # Si viene vacío, no se cambia
    stand_id = request.form.get('stand_id')

    # Actualizar datos básicos
    if username: usuario.username = username
    if stand_id: usuario.stand_id = stand_id
    
    # Solo cambiar clave si escribieron algo
    if password and password.strip():
        usuario.password_hash = generate_password_hash(password)
        usuario.must_change_password = True # Opcional: obligarlo a cambiarla de nuevo
        flash(f'Clave de {usuario.username} actualizada.', 'success')
    
    db.session.commit()
    flash(f'Datos de {usuario.username} actualizados.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN: EDITAR ANIMADOR ---
@app.route('/admin/editar_animador/<int:id>', methods=['POST'])
@login_required
def editar_animador(id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    usuario = User.query.get_or_404(id)
    
    # Actualizar nombre
    usuario.username = request.form.get('username')
    
    # Actualizar clave solo si se escribió una nueva
    password = request.form.get('password')
    if password and password.strip():
        usuario.password_hash = generate_password_hash(password)
        usuario.must_change_password = True # Opcional: obligarlo a cambiar de nuevo
    
    db.session.commit()
    flash(f'Datos del animador {usuario.username} actualizados.', 'success')
    return redirect(url_for('admin_dashboard'))


# --- CAMBIO DE CONTRASEÑA OBLIGATORIO ---
@app.route('/cambiar_password', methods=['GET', 'POST'])
@login_required
def cambiar_password():
    if request.method == 'POST':
        nueva_pass = request.form.get('password')
        confirm_pass = request.form.get('confirm_password')
        
        if nueva_pass != confirm_pass:
            flash('Las contraseñas no coinciden.', 'danger')
        elif len(nueva_pass) < 6:
            flash('La contraseña debe tener al menos 6 caracteres.', 'danger')
        else:
            # Guardar nueva clave
            current_user.password_hash = generate_password_hash(nueva_pass)
            current_user.must_change_password = False # ¡Ya cumplió!
            db.session.commit()
            
            flash('Contraseña actualizada correctamente. ¡Bienvenido!', 'success')
            
            # Redirigir según rol
            if current_user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif current_user.role == 'animador':
                return redirect(url_for('animador_dashboard'))
            else:
                return redirect(url_for('staff_dashboard'))
                
    return render_template('change_password.html')

# --- GESTIÓN: ELIMINAR ---
@app.route('/admin/eliminar_stand/<int:id>', methods=['POST'])
@login_required
def eliminar_stand(id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    stand = Stand.query.get_or_404(id)
    
    # 1. ¿Hay usuarios asignados a este stand?
    usuarios_asociados = User.query.filter_by(stand_id=stand.id).first()
    
    # 2. ¿Hay visitas registradas en este stand?
    visitas_asociadas = Visita.query.filter_by(stand_id=stand.id).first()

    if usuarios_asociados or visitas_asociadas:
        flash('⛔ No se puede eliminar: Este stand tiene historial (usuarios o visitas asociadas).', 'danger')
    else:
        db.session.delete(stand)
        db.session.commit()
        flash('✅ Stand eliminado correctamente.', 'success')
    # -------------------------------
        
    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN: ELIMINAR ANIMADOR ---
@app.route('/admin/eliminar_animador/<int:id>', methods=['POST'])
@login_required
def eliminar_animador(id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    animador = User.query.get_or_404(id)
    if animador.role != 'animador':
        flash('No puedes eliminar este usuario desde aquí.', 'danger')
        return redirect(url_for('admin_dashboard'))

    db.session.delete(animador)
    db.session.commit()
    flash('Animador eliminado correctamente.', 'success')
    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN: ELIMINAR STAFF ---
@app.route('/admin/eliminar_staff/<int:id>', methods=['POST'])
@login_required
def eliminar_staff(id):
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    usuario = User.query.get_or_404(id)
    if usuario.role == 'admin':
        flash('No puedes eliminar al Administrador principal.', 'danger')
    else:
        db.session.delete(usuario)
        db.session.commit()
        flash(f'Usuario {usuario.username} eliminado.', 'success')
        
    return redirect(url_for('admin_dashboard'))

# --- REPORTES Y EXPORTACIÓN ---
@app.route('/admin/exportar_reporte')
@login_required
def exportar_reporte():
    if current_user.role != 'admin': return redirect(url_for('login'))

    # Configurar Zona Horaria
    tz_chile = pytz.timezone('America/Santiago')

    # Creamos un archivo CSV en memoria
    si = io.StringIO()
    cw = csv.writer(si, delimiter=';') 
    
    # 1. REPORTE DE STAFF (Quién trabajó más)
    cw.writerow(["--- REPORTE DE RENDIMIENTO STAFF ---"])
    cw.writerow(["Usuario", "Stand Asignado", "Total Escaneos Realizados"])
    
    rendimiento = db.session.query(
        User.username, 
        Stand.nombre, 
        func.count(Visita.id)
    ).join(Visita, User.id == Visita.staff_id)\
     .join(Stand, Visita.stand_id == Stand.id)\
     .group_by(User.username, Stand.nombre).all()

    for user_name, stand_name, total in rendimiento:
        cw.writerow([user_name, stand_name, total])

    cw.writerow([])
    cw.writerow(["--- REPORTE POR STANDS ---"])
    cw.writerow(["Stand", "Tipo", "Total Visitas Recibidas"])
    stands = Stand.query.all()
    for stand in stands:
        total = Visita.query.filter_by(stand_id=stand.id).count()
        cw.writerow([stand.nombre, stand.tipo, total])

    cw.writerow([])
    cw.writerow(["--- DETALLE DE ESTUDIANTES ---"])
    cw.writerow(["RUT", "Nombre", "Carrera", "Total Visitas", "¿Recibió Regalo?", "Fecha Regalo"])
    
    estudiantes = Estudiante.query.all()
    for est in estudiantes:
        visitas = Visita.query.filter_by(estudiante_id=est.id).count()
        regalo = "SI" if est.tiene_regalo else "NO"
        fecha_str = "-"
        if est.fecha_entrega:
            fecha_obj = est.fecha_entrega
            # Si la fecha no tiene zona (naive), asumimos UTC
            if fecha_obj.tzinfo is None:
                fecha_obj = pytz.utc.localize(fecha_obj)
            # Convertir a Chile
            fecha_cl = fecha_obj.astimezone(tz_chile)
            fecha_str = fecha_cl.strftime("%d-%m-%Y %H:%M")
        cw.writerow([est.rut, est.nombre, est.carrera, visitas, regalo, fecha_str])

    # Preparar respuesta de descarga
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=reporte_induccion_2026.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# --- EXPORTAR MAESTRO COMPLETO ---
@app.route('/admin/exportar_maestro')
@login_required
def exportar_maestro():
    if current_user.role != 'admin': return redirect(url_for('login'))

    # Configurar Zona Horaria de Chile
    tz_chile = pytz.timezone('America/Santiago')

    # Crear el archivo en memoria
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';') # Excel en español prefiere punto y coma

    # 1. ESCRIBIR ENCABEZADOS
    headers = [
        'RUT', 'Nombre', 'Carrera', 'Email', 
        'Ganador Sorteo',               # Dato del sorteo
        '¿Recibió Regalo?',             # Estado regalo
        'Staff que entregó Regalo',     # Auditoría Staff
        'Fecha/Hora Entrega Regalo',    # Auditoría Hora
        'Detalle de Visitas (Stand - Staff - Hora)' # Auditoría Visitas
    ]
    writer.writerow(headers)

    # 2. RECORRER TODOS LOS ESTUDIANTES
    estudiantes = Estudiante.query.options(
        joinedload(Estudiante.staff_regalo),              # Carga staff que entregó regalo
        joinedload(Estudiante.visitas)                    # Carga todas las visitas
            .joinedload(Visita.stand),                    # Y sus stands
        joinedload(Estudiante.visitas)                    # Carga las visitas otra vez
            .joinedload(Visita.staff)                     # Y sus staff
    ).all()

    for est in estudiantes:
        # A. Formatear datos del Regalo
        nombre_staff_regalo = est.staff_regalo.username if est.staff_regalo else "N/A"
        
        fecha_regalo_str = "N/A"
        # Usamos la nueva columna fecha_entrega_regalo si existe, sino la antigua fecha_entrega
        fecha_raw = est.fecha_entrega_regalo or est.fecha_entrega
        
        if fecha_raw:
            # Si la fecha no tiene zona horaria (naive), asumimos UTC o le ponemos una
            if fecha_raw.tzinfo is None:
                fecha_raw = pytz.utc.localize(fecha_raw)
            
            # Convertir UTC a Chile
            fecha_cl = fecha_raw.astimezone(tz_chile)
            fecha_regalo_str = fecha_cl.strftime('%d-%m-%Y %H:%M:%S')

        # B. Recopilar todas las visitas (Auditoría de Scaneos)
        detalles_visitas = []
        for visita in est.visitas:
            # Manejo seguro de fechas de visita
            hora_visita = visita.timestamp
            
            if hora_visita is None:
                hora_fmt = "Sin fecha"
            else:
                if hora_visita.tzinfo is None:
                    hora_visita = pytz.utc.localize(hora_visita)
                hora_visita_cl = hora_visita.astimezone(tz_chile)
                hora_fmt = hora_visita_cl.strftime('%d-%m %H:%M')

            nombre_stand = visita.stand.nombre if visita.stand else "Stand Eliminado"
            nombre_staff = visita.staff.username if visita.staff else "Staff Eliminado"
            detalles_visitas.append(f"{nombre_stand} ({nombre_staff} - {hora_fmt})")
        
        visitas_str = " | ".join(detalles_visitas)

        # C. Escribir la fila
        writer.writerow([
            est.rut, 
            est.nombre, 
            est.carrera, 
            est.email,
            "SI" if est.es_ganador else "NO",   # <--- AQUÍ VES SI GANÓ EL SORTEO
            "SI" if est.tiene_regalo else "NO",
            nombre_staff_regalo,
            fecha_regalo_str,
            visitas_str
        ])

    # 3. GENERAR RESPUESTA DE DESCARGA
    output.seek(0)
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=reporte_completo_uls.csv"}
    )

# --- BOTÓN DE PÁNICO (RESET) ---
@app.route('/admin/reset_evento', methods=['POST'])
@login_required
def reset_evento():
    if current_user.role != 'admin': return redirect(url_for('login'))
    
    tipo_reset = request.form.get('tipo_reset') # 'todo' o 'solo_datos'
    
    try:
        if tipo_reset == 'solo_datos':
            # Borrar Historial (Visitas y Estudiantes) pero MANTENER Staff y Stands
            Visita.query.delete()
            Estudiante.query.delete()
            # Reiniciamos contadores de regalos entregados si los hubiere
            # (En tu caso se calculan dinámicamente, así que basta con borrar estudiantes)
            
            db.session.commit()
            flash('🧹 ¡Limpieza realizada! Se borraron todos los estudiantes y visitas. Stands y Staff intactos.', 'warning')
            
        elif tipo_reset == 'eliminar_stand_prueba':
            # Esta opción es específica para borrar SOLO visitas y permitir borrar stands
            Visita.query.delete()
            db.session.commit()
            flash('🧹 Historial de visitas borrado. Ahora puedes eliminar los Stands de prueba.', 'info')

    except Exception as e:
        db.session.rollback()
        flash(f'Error al resetear: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))

# --- GESTIÓN DEL SORTEO (ADMIN) ---
@app.route('/admin/gestion_sorteo', methods=['GET', 'POST'])
@login_required
def gestion_sorteo():
    if current_user.role != 'admin': return redirect(url_for('login'))

    # 1. Obtener todas las carreras únicas que existen en la base de datos
    # Esto busca en los alumnos cargados, así que si subiste el CSV, las carreras ya están aquí.
    carreras_query = db.session.query(Estudiante.carrera).distinct().order_by(Estudiante.carrera).all()
    todas_carreras = [c[0] for c in carreras_query if c[0]] # Lista limpia de nombres

    # 2. Recuperar configuración actual
    carreras_en_juego_str = Configuracion.get_valor('sorteo_carreras_en_juego', '')
    carreras_historial_str = Configuracion.get_valor('sorteo_carreras_historial', '')

    en_juego = carreras_en_juego_str.split(',') if carreras_en_juego_str else []
    historial = carreras_historial_str.split(',') if carreras_historial_str else []

    if request.method == 'POST':
        # El Admin seleccionó nuevas carreras
        seleccionadas = request.form.getlist('carreras_seleccionadas')
        accion = request.form.get('accion')

        if accion == 'guardar_bloque':
            # 1. Guardamos las seleccionadas como "En Juego"
            Configuracion.set_valor('sorteo_carreras_en_juego', ",".join(seleccionadas))
            
            # 2. Agregamos estas al historial (sin repetir)
            nuevo_historial = set(historial + seleccionadas)
            Configuracion.set_valor('sorteo_carreras_historial', ",".join(nuevo_historial))
            
            flash('✅ Bloque de sorteo actualizado. El Animador ya ve estas carreras.', 'success')

        elif accion == 'limpiar_historial':
            Configuracion.set_valor('sorteo_carreras_historial', '')
            flash('♻️ Historial reseteado. Todas las carreras pueden jugar de nuevo.', 'warning')
            
        elif accion == 'limpiar_bloque':
             Configuracion.set_valor('sorteo_carreras_en_juego', '')
             flash('⏹️ Bloque detenido. No hay carreras en juego.', 'info')

        return redirect(url_for('gestion_sorteo'))

    return render_template('admin_sorteo.html', 
                           carreras=todas_carreras, 
                           en_juego=en_juego, 
                           historial=historial)

# --- VISTAS HTML ---
@app.route('/animador')
@login_required
def vista_animador():
    # Solo admin o staff pueden ver el control remoto
    if not current_user.is_authenticated: return redirect(url_for('login'))
    return render_template('animador.html')

@app.route('/pantalla_publica')
def pantalla_publica():
    # Esta vista es pública (se proyecta en el telón)
    return render_template('pantalla_publica.html')


# --- LÓGICA SOCKETS (TIEMPO REAL) ---

@socketio.on('solicitar_sorteo')
def manejar_sorteo(data):
    print("🔴 1. SOCKET RECIBIDO: Sorteo solicitado.")
    
    # 1. Validar Configuración
    carreras_str = Configuracion.get_valor('sorteo_carreras_en_juego', '')
    if not carreras_str:
        emit('error_animador', {'msg': '⚠️ El Admin no ha habilitado carreras.'})
        return

    lista_carreras = carreras_str.split(',')

    # 2. BUSCAR CANDIDATOS (¡FILTRANDO QUE NO HAYAN GANADO!)
    candidatos = Estudiante.query.filter(
        Estudiante.carrera.in_(lista_carreras),
        Estudiante.es_ganador == False
    ).all()

    print(f"🔵 Candidatos disponibles: {len(candidatos)}")

    if not candidatos:
        emit('error_animador', {'msg': '⚠️ Ya no quedan estudiantes sin premio en este grupo.'})
        return

    # 3. Elegir Ganador
    ganador = random.choice(candidatos)
    
    # 4. Obtener nombres para la animación (mezcla de candidatos reales)
    # Tomamos hasta 40 nombres aleatorios de la lista actual para el efecto visual
    pool_nombres = random.sample(candidatos, k=min(len(candidatos), 40))
    lista_nombres_animacion = [est.nombre for est in pool_nombres]
    lista_carreras_animacion = [est.carrera for est in pool_nombres]

    # 5. MARCARLO COMO GANADOR (Para que no salga de nuevo)
    ganador.es_ganador = True
    db.session.commit()
    print(f"🟢 GANADOR: {ganador.nombre} (Marcado en DB)")

    # 6. Enviar a Pantalla
    emit('iniciar_animacion', {
        'nombre': ganador.nombre,
        'carrera': ganador.carrera,
        'rut_oculto': f"***{ganador.rut[-4:]}",
        'nombres_azar': lista_nombres_animacion,
        'carreras_azar': lista_carreras_animacion
    }, broadcast=True)

@socketio.on('reset_pantalla')
def manejar_reset_pantalla():
    """
    Limpia la pantalla pública, volviendo al estado inicial.
    Broadcast a todas las pantallas conectadas.
    """
    print("🧹 RESET: Limpiando pantalla pública")
    emit('limpiar_pantalla', broadcast=True)
    print("✅ RESET: Señal enviada")


# --- REPORTE DETALLADO POR CARRERAS ---
@app.route('/admin/avance_carreras')
@login_required
def avance_carreras():
    # 1. Seguridad
    if current_user.role != 'admin': 
        return redirect(url_for('login'))
    
    # 2. La consulta mágica (Agrupar por carrera y contar regalos)
    # Explicación: 
    # - func.count: Cuenta cuántos alumnos hay en total por carrera
    # - func.sum(case...): Suma 1 solo si tiene_regalo es True
    stats = db.session.query(
        Estudiante.carrera,
        func.count(Estudiante.id).label('total'),
        func.sum(case((Estudiante.tiene_regalo == True, 1), else_=0)).label('entregados')
    ).group_by(Estudiante.carrera).order_by(Estudiante.carrera).all()

    return render_template('regalo_carrera.html', stats=stats)