# database.py - DATABASE MODELS AND CONFIGURATION

import os
import sqlite3
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import string
import sqlalchemy

db = SQLAlchemy()

# =================================================================
# === DATABASE CONNECTION HELPER ===
# =================================================================

def get_db_engine():
    """
    Initializes a database connection engine for Cloud SQL Unix socket connection.
    """
    # Get Cloud SQL connection parameters from environment variables
    db_user = os.environ.get("DB_USER")
    db_pass = os.environ.get("DB_PASS")
    db_name = os.environ.get("DB_NAME")
    unix_socket_path = os.environ.get("INSTANCE_UNIX_SOCKET")
    
    if not all([db_user, db_pass, db_name, unix_socket_path]):
        raise ValueError("Missing required Cloud SQL environment variables: DB_USER, DB_PASS, DB_NAME, INSTANCE_UNIX_SOCKET")

    # PostgreSQL requires a specific suffix for the socket path.
    unix_socket_path = f"{unix_socket_path}/.s.PGSQL.5432"

    # Construct the connection URL for the Unix socket.
    db_uri = f"postgresql+pg8000://{db_user}:{db_pass}@/{db_name}?unix_sock={unix_socket_path}"
    
    engine = sqlalchemy.create_engine(db_uri)
    return engine

def get_database_uri():
    """
    Get the database URI for SQLAlchemy configuration using Cloud SQL Unix socket connection.
    """
    # Get Cloud SQL connection parameters from environment variables
    db_user = os.environ.get("DB_USER")
    db_pass = os.environ.get("DB_PASS")
    db_name = os.environ.get("DB_NAME")
    unix_socket_path = os.environ.get("INSTANCE_UNIX_SOCKET")
    
    if not all([db_user, db_pass, db_name, unix_socket_path]):
        raise ValueError("Missing required Cloud SQL environment variables: DB_USER, DB_PASS, DB_NAME, INSTANCE_UNIX_SOCKET")

    # PostgreSQL requires a specific suffix for the socket path.
    unix_socket_path = f"{unix_socket_path}/.s.PGSQL.5432"

    # Construct the connection URL for the Unix socket.
    return f"postgresql+pg8000://{db_user}:{db_pass}@/{db_name}?unix_sock={unix_socket_path}"

# =================================================================
# === DATABASE MODELS ===
# =================================================================

class User(db.Model):
    """User model for authentication and authorization."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('doctor', 'assistant', 'administrator', name='user_roles'), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # Relationships
    sessions = db.relationship('UserSession', backref='user', lazy=True, cascade='all, delete-orphan')
    mfa_codes = db.relationship('MfaCode', backref='user', lazy=True, cascade='all, delete-orphan')
    doctor_patients = db.relationship('DoctorPatient', backref='doctor', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hash and set the user's password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if the provided password matches the user's password."""
        return check_password_hash(self.password_hash, password)
    
    def get_full_name(self):
        """Get the user's full name."""
        return f"{self.first_name} {self.last_name}"
    
    def to_dict(self):
        """Convert user object to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'email': self.email,
            'role': self.role,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.get_full_name(),
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class UserSession(db.Model):
    """User session model for session management and timeout."""
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False, index=True)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    @staticmethod
    def generate_session_token():
        """Generate a secure random session token."""
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(64))
    
    def is_expired(self):
        """Check if the session has expired."""
        return datetime.utcnow() > self.expires_at
    
    def update_activity(self):
        """Update the last activity timestamp."""
        self.last_activity = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        """Convert session object to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'session_token': self.session_token,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'ip_address': self.ip_address,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class MfaCode(db.Model):
    """MFA code model for two-factor authentication."""
    __tablename__ = 'mfa_codes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code = db.Column(db.String(6), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    @staticmethod
    def generate_mfa_code():
        """Generate a 6-digit MFA code."""
        return ''.join(secrets.choice(string.digits) for _ in range(6))
    
    def is_expired(self):
        """Check if the MFA code has expired."""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self):
        """Check if the MFA code is valid (not used and not expired)."""
        return not self.used and not self.is_expired()


class DoctorPatient(db.Model):
    """Doctor-Patient relationship model for access control."""
    __tablename__ = 'doctor_patients'
    
    id = db.Column(db.Integer, primary_key=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    patient_id = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    # Unique constraint to prevent duplicate relationships
    __table_args__ = (db.UniqueConstraint('doctor_id', 'patient_id', name='unique_doctor_patient'),)


class AuditLog(db.Model):
    """Audit log model for tracking authentication and access events."""
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.Text, nullable=True)
    severity = db.Column(db.Enum('INFO', 'WARN', 'ERROR', name='log_severity'), default='INFO', nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    
    def to_syslog_format(self):
        """Convert audit log to syslog format for Google Cloud Storage."""
        hostname = os.getenv('HOSTNAME', 'medical-app')
        app_name = 'medical-transcription'
        timestamp_str = self.timestamp.strftime('%Y-%m-%dT%H:%M:%SZ')
        
        user_info = f"user_{self.user_id}" if self.user_id else "anonymous"
        resource_info = f" {self.resource}" if self.resource else ""
        details_info = f" {self.details}" if self.details else ""
        
        return f"{timestamp_str} {hostname} {app_name}: {self.severity} {user_info} {self.action}{resource_info}{details_info}"


# =================================================================
# === DATABASE HELPER FUNCTIONS ===
# =================================================================

def init_database(app):
    """Initialize the database with the Flask app."""
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        
        # Create default administrator if it doesn't exist
        admin_user = User.query.filter_by(email='dev.madnansultan@gmail.com').first()
        if not admin_user:
            admin_user = User(
                email='dev.madnansultan@gmail.com',
                role='administrator',
                first_name='System',
                last_name='Administrator',
                is_active=True
            )
            admin_user.set_password('admin123')  # Change this in production
            db.session.add(admin_user)
            db.session.commit()
            print("Default administrator created: admin@medical-app.com / admin123")


def cleanup_expired_sessions():
    """Remove expired sessions from the database."""
    expired_sessions = UserSession.query.filter(UserSession.expires_at < datetime.utcnow()).all()
    for session in expired_sessions:
        db.session.delete(session)
    db.session.commit()
    return len(expired_sessions)


def cleanup_expired_mfa_codes():
    """Remove expired MFA codes from the database."""
    expired_codes = MfaCode.query.filter(MfaCode.expires_at < datetime.utcnow()).all()
    for code in expired_codes:
        db.session.delete(code)
    db.session.commit()
    return len(expired_codes)


def get_user_accessible_patients(user_id, role):
    """Get list of patient IDs that the user has access to based on their role."""
    if role == 'administrator':
        # Administrators have access to all patients
        # This would need to be implemented based on your patient storage system
        return None  # None means access to all
    elif role == 'doctor':
        # Doctors have access to their assigned patients
        doctor_patients = DoctorPatient.query.filter_by(doctor_id=user_id).all()
        return [dp.patient_id for dp in doctor_patients]
    else:  # assistant
        # Assistants have no direct patient access
        return []


def assign_patient_to_doctor(doctor_id, patient_id):
    """Assign a patient to a doctor."""
    # Check if the doctor exists and has the correct role
    doctor = User.query.filter_by(id=doctor_id, role='doctor', is_active=True).first()
    if not doctor:
        return False, "Doctor not found or inactive"
    
    # Check if the relationship already exists
    existing_relationship = DoctorPatient.query.filter_by(
        doctor_id=doctor_id, 
        patient_id=patient_id
    ).first()
    
    if existing_relationship:
        return False, "Patient already assigned to this doctor"
    
    # Create the relationship
    doctor_patient = DoctorPatient(doctor_id=doctor_id, patient_id=patient_id)
    db.session.add(doctor_patient)
    db.session.commit()
    
    return True, "Patient successfully assigned to doctor"
