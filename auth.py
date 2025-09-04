# auth.py - AUTHENTICATION AND AUTHORIZATION SERVICES

import os
import json
from google.cloud import storage
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, get_jwt
from flask_mail import Mail, Message
from database import db, User, UserSession, MfaCode, AuditLog, cleanup_expired_sessions, cleanup_expired_mfa_codes

# =================================================================
# === AUTHENTICATION CONFIGURATION ===
# =================================================================

jwt = JWTManager()
mail = Mail()

# Session timeout in minutes
SESSION_TIMEOUT_MINUTES = 30

# MFA code expiration in minutes
MFA_CODE_EXPIRATION_MINUTES = 10

# Google Cloud Storage configuration for audit logs
AUDIT_LOG_BUCKET = os.getenv('AUDIT_LOG_BUCKET', 'medical-app-audit-logs')


# =================================================================
# === JWT CONFIGURATION ===
# =================================================================

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    """Handle expired JWT tokens."""
    log_authentication_event(
        user_id=jwt_payload.get('sub'),
        action='TOKEN_EXPIRED',
        severity='WARN',
        details='JWT token has expired'
    )
    return jsonify({'error': 'Token has expired', 'code': 'TOKEN_EXPIRED'}), 401


@jwt.invalid_token_loader
def invalid_token_callback(error):
    """Handle invalid JWT tokens."""
    log_authentication_event(
        action='INVALID_TOKEN',
        severity='WARN',
        details=f'Invalid token: {error}'
    )
    return jsonify({'error': 'Invalid token', 'code': 'INVALID_TOKEN'}), 401


@jwt.unauthorized_loader
def missing_token_callback(error):
    """Handle missing JWT tokens."""
    log_authentication_event(
        action='MISSING_TOKEN',
        severity='WARN',
        details='Authorization token is required'
    )
    return jsonify({'error': 'Authorization token is required', 'code': 'MISSING_TOKEN'}), 401


# =================================================================
# === AUTHENTICATION HELPER FUNCTIONS ===
# =================================================================

def get_client_ip():
    """Get the client's IP address from the request."""
    if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
        return request.environ['REMOTE_ADDR']
    else:
        return request.environ['HTTP_X_FORWARDED_FOR']


def get_user_agent():
    """Get the client's user agent from the request."""
    return request.headers.get('User-Agent', '')


def create_user_session(user_id, expires_in_minutes=SESSION_TIMEOUT_MINUTES):
    """Create a new user session."""
    # Clean up expired sessions first
    cleanup_expired_sessions()
    
    session_token = UserSession.generate_session_token()
    expires_at = datetime.now() + timedelta(minutes=expires_in_minutes)
    
    user_session = UserSession(
        user_id=user_id,
        session_token=session_token,
        expires_at=expires_at,
        ip_address=get_client_ip(),
        user_agent=get_user_agent()
    )
    
    db.session.add(user_session)
    db.session.commit()
    
    return user_session


def validate_session(session_token):
    """Validate a user session and update activity."""
    session = UserSession.query.filter_by(session_token=session_token).first()
    
    if not session:
        return None, "Session not found"
    
    if session.is_expired():
        db.session.delete(session)
        db.session.commit()
        return None, "Session expired"
    
    # Update last activity
    session.update_activity()
    
    return session, None


def create_mfa_code(user_id):
    """Create a new MFA code for the user."""
    # Clean up expired codes first
    cleanup_expired_mfa_codes()
    
    # Invalidate any existing unused codes for this user
    existing_codes = MfaCode.query.filter_by(user_id=user_id, used=False).all()
    for code in existing_codes:
        code.used = True
    
    # Create new MFA code
    mfa_code = MfaCode(
        user_id=user_id,
        code=MfaCode.generate_mfa_code(),
        expires_at=datetime.utcnow() + timedelta(minutes=MFA_CODE_EXPIRATION_MINUTES)
    )
    
    db.session.add(mfa_code)
    db.session.commit()
    
    return mfa_code


def validate_mfa_code(user_id, code):
    """Validate an MFA code for the user."""
    mfa_code = MfaCode.query.filter_by(
        user_id=user_id,
        code=code,
        used=False
    ).first()
    
    if not mfa_code:
        return False, "Invalid MFA code"
    
    if mfa_code.is_expired():
        return False, "MFA code has expired"
    
    # Mark the code as used
    mfa_code.used = True
    db.session.commit()
    
    return True, "MFA code validated successfully"


def send_mfa_code_email(user, mfa_code):
    """Send MFA code via email."""
    try:
        msg = Message(
            subject='Medical App - Two-Factor Authentication Code',
            sender=current_app.config['MAIL_DEFAULT_SENDER'],
            recipients=[user.email]
        )
        
        msg.html = f"""
        <html>
        <body>
            <h2>Two-Factor Authentication</h2>
            <p>Hello {user.get_full_name()},</p>
            <p>Your verification code is:</p>
            <h1 style="color: #007bff; font-size: 32px; letter-spacing: 5px;">{mfa_code.code}</h1>
            <p>This code will expire in {MFA_CODE_EXPIRATION_MINUTES} minutes.</p>
            <p>If you did not request this code, please contact your administrator immediately.</p>
            <br>
            <p>Best regards,<br>Medical Transcription System</p>
        </body>
        </html>
        """
        
        mail.send(msg)
        return True, "MFA code sent successfully"
    
    except Exception as e:
        return False, f"Failed to send MFA code: {str(e)}"


# =================================================================
# === AUDIT LOGGING FUNCTIONS ===
# =================================================================

def log_authentication_event(user_id=None, action=None, resource=None, details=None, severity='INFO'):
    """Log authentication events to database and Google Cloud Storage."""
    try:
        # Create audit log entry
        audit_log = AuditLog(
            user_id=user_id,
            action=action,
            resource=resource,
            details=details,
            ip_address=get_client_ip(),
            user_agent=get_user_agent(),
            severity=severity
        )
        
        db.session.add(audit_log)
        db.session.commit()
        
        # Send to Google Cloud Storage in syslog format
        send_audit_log_to_gcs(audit_log)
        
    except Exception as e:
        print(f"Error logging authentication event: {e}")


def log_access_event(user_id, action, resource=None, details=None):
    """Log data access events."""
    log_authentication_event(
        user_id=user_id,
        action=action,
        resource=resource,
        details=details,
        severity='INFO'
    )


def send_audit_log_to_gcs(audit_log):
    """Send audit log to Google Cloud Storage bucket in syslog format."""
    try:
        # Initialize Google Cloud Storage client
        storage_client = storage.Client()
        bucket = storage_client.bucket(AUDIT_LOG_BUCKET)
        
        # Generate GCS object key with date partitioning
        date_str = audit_log.timestamp.strftime('%Y/%m/%d')
        timestamp_str = audit_log.timestamp.strftime('%Y%m%d_%H%M%S')
        gcs_key = f"audit-logs/{date_str}/medical-app-{timestamp_str}-{audit_log.id}.log"
        
        # Convert to syslog format
        log_content = audit_log.to_syslog_format()
        
        # Upload to Google Cloud Storage
        blob = bucket.blob(gcs_key)
        blob.upload_from_string(log_content, content_type='text/plain')
        
    except Exception as e:
        print(f"Error sending audit log to Google Cloud Storage: {e}")


# =================================================================
# === AUTHORIZATION DECORATORS ===
# =================================================================

def role_required(allowed_roles):
    """Decorator to require specific roles for route access."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get current user from JWT
            current_user_id = int(get_jwt_identity())
            if not current_user_id:
                return jsonify({'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}), 401
            
            # Get user from database
            user = User.query.get(current_user_id)
            if not user or not user.is_active:
                log_authentication_event(
                    user_id=current_user_id,
                    action='ACCESS_DENIED',
                    severity='WARN',
                    details='User not found or inactive'
                )
                return jsonify({'error': 'User not found or inactive', 'code': 'USER_INACTIVE'}), 401
            
            # Check role authorization
            if user.role not in allowed_roles:
                log_access_event(
                    user_id=current_user_id,
                    action='UNAUTHORIZED_ACCESS_ATTEMPT',
                    resource=request.endpoint,
                    details=f'User role {user.role} not in allowed roles {allowed_roles}'
                )
                return jsonify({'error': 'Insufficient permissions', 'code': 'INSUFFICIENT_PERMISSIONS'}), 403
            
            # Log successful access
            log_access_event(
                user_id=current_user_id,
                action='ROUTE_ACCESS',
                resource=request.endpoint,
                details=f'User with role {user.role} accessed {request.method} {request.path}'
            )
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def patient_access_required(f):
    """Decorator to check if user has access to the requested patient."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get current user from JWT
        current_user_id = int(get_jwt_identity())
        user = User.query.get(current_user_id)
        
        # Get patient_id from request (could be in URL params, JSON body, or query params)
        patient_id = None
        if 'patient_id' in kwargs:
            patient_id = kwargs['patient_id']
        elif request.json and 'patient_id' in request.json:
            patient_id = request.json['patient_id']
        elif request.args.get('patient_id'):
            patient_id = request.args.get('patient_id')
        
        if not patient_id:
            return jsonify({'error': 'Patient ID required', 'code': 'PATIENT_ID_REQUIRED'}), 400
        
        # Check patient access based on user role
        from database import get_user_accessible_patients
        accessible_patients = get_user_accessible_patients(current_user_id, user.role)
        
        # Administrators have access to all patients (accessible_patients = None)
        if accessible_patients is not None and patient_id not in accessible_patients:
            log_access_event(
                user_id=current_user_id,
                action='UNAUTHORIZED_PATIENT_ACCESS',
                resource=f'patient_{patient_id}',
                details=f'User attempted to access patient {patient_id} without permission'
            )
            return jsonify({'error': 'Access denied to this patient', 'code': 'PATIENT_ACCESS_DENIED'}), 403
        
        # Log successful patient access
        log_access_event(
            user_id=current_user_id,
            action='PATIENT_DATA_ACCESS',
            resource=f'patient_{patient_id}',
            details=f'User accessed data for patient {patient_id}'
        )
        
        return f(*args, **kwargs)
    return decorated_function


def log_access(f):
    """Decorator to log all access to protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user_id = int(get_jwt_identity())
        
        # Log the access attempt
        log_access_event(
            user_id=current_user_id,
            action='API_ACCESS',
            resource=f'{request.method} {request.endpoint}',
            details=f'Accessed {request.path} with args: {dict(request.args)}'
        )
        
        return f(*args, **kwargs)
    return decorated_function


def require_active_session(f):
    """Decorator to enforce active (non-expired) server-side session on protected routes.
    Requires the client to send X-Session-Token header. If the session is expired
    or missing, responds with 401 SESSION_INVALID.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not check_session_timeout():
            return jsonify({'error': 'Session expired', 'code': 'SESSION_INVALID'}), 401
        return f(*args, **kwargs)
    return decorated_function


# =================================================================
# === SESSION MANAGEMENT FUNCTIONS ===
# =================================================================

def check_session_timeout():
    """Check and handle session timeout for the current user."""
    try:
        # Get session token from request headers
        session_token = request.headers.get('X-Session-Token')
        if not session_token:
            return True  # No session token, let JWT handle it
        
        session, error = validate_session(session_token)
        if error:
            log_authentication_event(
                action='SESSION_TIMEOUT',
                severity='INFO',
                details=f'Session validation failed: {error}'
            )
            return False
        
        return True
    
    except Exception as e:
        print(f"Error checking session timeout: {e}")
        return True  # Don't block on errors


def extend_session(session_token):
    """Extend a user session."""
    session = UserSession.query.filter_by(session_token=session_token).first()
    if session and not session.is_expired():
        session.expires_at = datetime.utcnow() + timedelta(minutes=SESSION_TIMEOUT_MINUTES)
        session.update_activity()
        return True
    return False


def revoke_user_sessions(user_id):
    """Revoke all sessions for a specific user."""
    sessions = UserSession.query.filter_by(user_id=user_id).all()
    for session in sessions:
        db.session.delete(session)
    db.session.commit()
    
    log_authentication_event(
        user_id=user_id,
        action='ALL_SESSIONS_REVOKED',
        severity='INFO',
        details='All user sessions have been revoked'
    )
    
    return len(sessions)
