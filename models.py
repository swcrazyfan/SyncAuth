from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy (import and init in app.py)
db = SQLAlchemy()

class MasterConfig(db.Model):
    __tablename__ = 'master_config'
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(256), nullable=False)
    api_key = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class Client(db.Model):
    __tablename__ = 'clients'
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(128), nullable=False)
    device_id = db.Column(db.String(64), nullable=False)
    address = db.Column(db.String(256), nullable=False)
    api_key = db.Column(db.String(256), nullable=False)
    sync_enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class SyncHistory(db.Model):
    __tablename__ = 'sync_history'
    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.Integer, db.ForeignKey('clients.id'), nullable=False)
    status = db.Column(db.String(32), nullable=False)
    message = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class SchedulePreference(db.Model):
    __tablename__ = 'schedule_preferences'
    id = db.Column(db.Integer, primary_key=True)
    frequency = db.Column(db.String(32), nullable=False)
    custom_type = db.Column(db.String(32))
    interval_value = db.Column(db.Integer)
    interval_unit = db.Column(db.String(16))
    sync_time = db.Column(db.String(5))  # HH:MM
    sync_days = db.Column(db.String(32))  # comma-separated weekdays
    show_notifications = db.Column(db.Boolean, default=False)
    quiet_hours_enabled = db.Column(db.Boolean, default=False)
    quiet_hours_start = db.Column(db.String(5))
    quiet_hours_end = db.Column(db.String(5))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

