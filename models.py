from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import pyotp
import base64
import os

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    
    # MFA fields
    mfa_secret = db.Column(db.String(32), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    
    resources = db.relationship('Resource', backref='owner', lazy=True)
    access_logs = db.relationship('AccessLog', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_mfa_secret(self):
        """Generate a new MFA secret for the user"""
        self.mfa_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
        return self.mfa_secret
    
    def get_totp_uri(self):
        """Get the TOTP URI for QR code generation"""
        return pyotp.totp.TOTP(self.mfa_secret).provisioning_uri(
            name=self.username,
            issuer_name="Zero Trust Flask App"
        )
    
    def verify_totp(self, token):
        """Verify a TOTP token"""
        if not self.mfa_enabled or not self.mfa_secret:
            return False
        totp = pyotp.TOTP(self.mfa_secret)
        return totp.verify(token)
    
    def to_dict(self):
        return {
            'username': self.username,
            'role': self.role,
            'mfa_enabled': self.mfa_enabled
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