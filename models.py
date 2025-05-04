from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    resources = db.relationship('Resource', backref='owner', lazy=True)
    access_logs = db.relationship('AccessLog', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'username': self.username,
            'role': self.role
        }

class Resource(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_public = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    access_logs = db.relationship('AccessLog', backref='resource', lazy=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'content': self.content,
            'owner': self.owner.username,
            'is_public': self.is_public
        }

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(36), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    action = db.Column(db.String(20), nullable=False)  # 'read', 'write', 'login', etc.
    success = db.Column(db.Boolean, default=True)
    ip_address = db.Column(db.String(45), nullable=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=True)
    
    def to_dict(self):
        return {
            'request_id': self.request_id,
            'timestamp': self.timestamp.isoformat(),
            'action': self.action,
            'success': self.success,
            'user': self.user.username if self.user else None,
            'resource': self.resource.name if self.resource else None
        }