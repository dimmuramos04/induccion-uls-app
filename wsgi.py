# wsgi.py
import eventlet
eventlet.monkey_patch()

try:
    from psycogreen.eventlet import patch_psycopg
    patch_psycopg()
    print("psycogreen patch applied successfully.")
except ImportError:
    print("psycogreen not found, database connections might block.")

from app import create_app, socketio

app = create_app()