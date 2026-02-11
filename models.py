from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import uuid
from flask_socketio import SocketIO
from sqlalchemy.sql import func
from sqlalchemy import Index

db = SQLAlchemy()
socketio = SocketIO()

# --- TABLAS DE CONFIGURACIÓN ---

class Configuracion(db.Model):
    __tablename__ = 'configuracion'
    id = db.Column(db.Integer, primary_key=True)
    clave = db.Column(db.String(50), unique=True, nullable=False) 
    valor = db.Column(db.String(500), nullable=False)
    # --- MÉTODOS AYUDANTES NUEVOS ---
    @staticmethod
    def get_valor(clave, default=None):
        conf = Configuracion.query.filter_by(clave=clave).first()
        return conf.valor if conf else default

    @staticmethod
    def set_valor(clave, nuevo_valor):
        conf = Configuracion.query.filter_by(clave=clave).first()
        if conf:
            conf.valor = str(nuevo_valor)
        else:
            db.session.add(Configuracion(clave=clave, valor=str(nuevo_valor)))
        db.session.commit()

class Stand(db.Model):
    __tablename__ = 'stand'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    tipo = db.Column(db.String(20), default='servicio') # 'servicio' | 'entrega'
    icono = db.Column(db.String(50), default='fa-map-marker-alt')
    
    # Relaciones
    staff = db.relationship('User', backref='stand_asignado', lazy=True)
    visitas = db.relationship('Visita', back_populates='stand', lazy=True)

class Bloque(db.Model):
    __tablename__ = 'bloque'
    id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    activo = db.Column(db.Boolean, default=False)
    estudiantes = db.relationship('Estudiante', backref='bloque', lazy=True)

# --- USUARIOS (STAFF/ADMIN) ---

class User(UserMixin, db.Model): # <--- Nota el UserMixin aquí
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='staff') # 'admin' | 'staff'
    stand_id = db.Column(db.Integer, db.ForeignKey('stand.id'), nullable=True)
    must_change_password = db.Column(db.Boolean, default=False)

# --- ESTUDIANTES Y OPERACIÓN ---

class Estudiante(db.Model):
    __tablename__ = 'estudiante'
    id = db.Column(db.Integer, primary_key=True)
    rut = db.Column(db.String(12), unique=True, index=True, nullable=False)
    nombre = db.Column(db.String(150), nullable=False)
    carrera = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=True)
    es_ganador = db.Column(db.Boolean, default=False)
    staff_regalo_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    fecha_entrega_regalo = db.Column(db.DateTime, nullable=True)
    staff_regalo = db.relationship('User', foreign_keys=[staff_regalo_id])
    
    bloque_id = db.Column(db.Integer, db.ForeignKey('bloque.id'), nullable=True)
    tiene_regalo = db.Column(db.Boolean, default=False)
    fecha_entrega = db.Column(db.DateTime, nullable=True)
    token_uuid = db.Column(db.String(36), default=lambda: str(uuid.uuid4()), unique=True)
    
    visitas = db.relationship('Visita', backref='estudiante', lazy=True)
    encuesta = db.relationship('Encuesta', backref='estudiante', uselist=False, lazy=True)

class Visita(db.Model):
    __tablename__ = 'visita'
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime(timezone=True), server_default=func.now())
    estudiante_id = db.Column(db.Integer, db.ForeignKey('estudiante.id'), nullable=False)
    stand_id = db.Column(db.Integer, db.ForeignKey('stand.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    staff = db.relationship('User')
    stand = db.relationship('Stand', back_populates='visitas')
    __table_args__ = (
        db.UniqueConstraint('estudiante_id', 'stand_id', name='una_visita_por_stand'),
        db.Index('idx_visita_estudiante', 'estudiante_id'),
        db.Index('idx_visita_stand', 'stand_id'),
    )

class Encuesta(db.Model):
    __tablename__ = 'encuesta'
    id = db.Column(db.Integer, primary_key=True)
    estudiante_id = db.Column(db.Integer, db.ForeignKey('estudiante.id'), nullable=False)
    evaluacion = db.Column(db.Integer, nullable=False)
    comentario = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)