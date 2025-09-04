# auth_routes.py - AUTHENTICATION API ROUTES

import os
from datetime import datetime, timedelta
from flask import request, jsonify, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from database import db, User, UserSession, MfaCode, assign_patient_to_doctor
from auth import (
    create_user_session, validate_session, create_mfa_code, validate_mfa_code,
    send_mfa_code_email, log_authentication_event, log_access_event,
    role_required, get_client_ip, get_user_agent, revoke_user_sessions,
    require_active_session
)

# =================================================================
# === AUTHENTICATION ROUTES ===
# =================================================================

def register_auth_routes(app):
    """Register all authentication routes with the Flask app."""
    
    @app.route("/api/auth/login", methods=['POST'])
    def login():
        """User login endpoint - first step of authentication."""
        try:
            data = request.get_json()
            if not data or 'email' not in data or 'password' not in data:
                log_authentication_event(
                    action='LOGIN_FAILED',
                    severity='WARN',
                    details='Missing email or password in request'
                )
                return jsonify({'error': 'Email and password are required', 'code': 'MISSING_CREDENTIALS'}), 400
            
            email = data['email'].lower().strip()
            password = data['password']
            
            # Find user by email
            user = User.query.filter_by(email=email).first()
            
            if not user or not user.check_password(password):
                log_authentication_event(
                    action='LOGIN_FAILED',
                    severity='WARN',
                    details=f'Invalid credentials for email: {email}'
                )
                return jsonify({'error': 'Invalid email or password', 'code': 'INVALID_CREDENTIALS'}), 401
            
            if not user.is_active:
                log_authentication_event(
                    user_id=user.id,
                    action='LOGIN_FAILED',
                    severity='WARN',
                    details='User account is inactive'
                )
                return jsonify({'error': 'Account is inactive', 'code': 'ACCOUNT_INACTIVE'}), 401
            
            # Create and send MFA code
            mfa_code = create_mfa_code(user.id)
            success, message = send_mfa_code_email(user, mfa_code)
            
            if not success:
                log_authentication_event(
                    user_id=user.id,
                    action='MFA_SEND_FAILED',
                    severity='ERROR',
                    details=f'Failed to send MFA code: {message}'
                )
                return jsonify({'error': 'Failed to send verification code', 'code': 'MFA_SEND_FAILED'}), 500
            
            log_authentication_event(
                user_id=user.id,
                action='LOGIN_SUCCESS_MFA_SENT',
                severity='INFO',
                details=f'User {email} logged in successfully, MFA code sent'
            )
            
            return jsonify({
                'message': 'Login successful. Please check your email for the verification code.',
                'user_id': user.id,
                'mfa_required': True,
                'code': 'MFA_REQUIRED'
            }), 200
            
        except Exception as e:
            log_authentication_event(
                action='LOGIN_ERROR',
                severity='ERROR',
                details=f'Login error: {str(e)}'
            )
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/auth/verify-mfa", methods=['POST'])
    def verify_mfa():
        """Verify MFA code and complete authentication."""
        try:
            data = request.get_json()
            if not data or 'user_id' not in data or 'mfa_code' not in data:
                log_authentication_event(
                    action='MFA_VERIFICATION_FAILED',
                    severity='WARN',
                    details='Missing user_id or mfa_code in request'
                )
                return jsonify({'error': 'User ID and MFA code are required', 'code': 'MISSING_MFA_DATA'}), 400
            
            user_id = data['user_id']
            mfa_code = data['mfa_code']
            
            # Validate user
            user = User.query.get(user_id)
            if not user or not user.is_active:
                log_authentication_event(
                    user_id=user_id,
                    action='MFA_VERIFICATION_FAILED',
                    severity='WARN',
                    details='User not found or inactive during MFA verification'
                )
                return jsonify({'error': 'Invalid user', 'code': 'INVALID_USER'}), 401
            
            # Validate MFA code
            is_valid, message = validate_mfa_code(user_id, mfa_code)
            
            if not is_valid:
                log_authentication_event(
                    user_id=user_id,
                    action='MFA_VERIFICATION_FAILED',
                    severity='WARN',
                    details=f'MFA verification failed: {message}'
                )
                return jsonify({'error': message, 'code': 'INVALID_MFA_CODE'}), 401
            
            # Create JWT token
            access_token = create_access_token(
                identity=str(user.id),
                expires_delta=timedelta(hours=24)
            )
            
            # Create user session
            user_session = create_user_session(user.id)
            
            log_authentication_event(
                user_id=user.id,
                action='AUTHENTICATION_COMPLETE',
                severity='INFO',
                details=f'User {user.email} completed authentication successfully'
            )
            
            return jsonify({
                'message': 'Authentication successful',
                'access_token': access_token,
                'session_token': user_session.session_token,
                'user': user.to_dict(),
                'expires_at': user_session.expires_at.isoformat(),
                'code': 'AUTH_SUCCESS'
            }), 200
            
        except Exception as e:
            log_authentication_event(
                action='MFA_VERIFICATION_ERROR',
                severity='ERROR',
                details=f'MFA verification error: {str(e)}'
            )
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/auth/resend-mfa", methods=['POST'])
    def resend_mfa():
        """Resend MFA code to user's email."""
        try:
            data = request.get_json()
            if not data or 'user_id' not in data:
                return jsonify({'error': 'User ID is required', 'code': 'MISSING_USER_ID'}), 400
            
            user_id = data['user_id']
            user = User.query.get(user_id)
            
            if not user or not user.is_active:
                log_authentication_event(
                    user_id=user_id,
                    action='MFA_RESEND_FAILED',
                    severity='WARN',
                    details='User not found or inactive during MFA resend'
                )
                return jsonify({'error': 'Invalid user', 'code': 'INVALID_USER'}), 401
            
            # Create and send new MFA code
            mfa_code = create_mfa_code(user.id)
            success, message = send_mfa_code_email(user, mfa_code)
            
            if not success:
                log_authentication_event(
                    user_id=user.id,
                    action='MFA_RESEND_FAILED',
                    severity='ERROR',
                    details=f'Failed to resend MFA code: {message}'
                )
                return jsonify({'error': 'Failed to send verification code', 'code': 'MFA_SEND_FAILED'}), 500
            
            log_authentication_event(
                user_id=user.id,
                action='MFA_RESENT',
                severity='INFO',
                details=f'MFA code resent to {user.email}'
            )
            
            return jsonify({
                'message': 'Verification code sent successfully',
                'code': 'MFA_RESENT'
            }), 200
            
        except Exception as e:
            log_authentication_event(
                action='MFA_RESEND_ERROR',
                severity='ERROR',
                details=f'MFA resend error: {str(e)}'
            )
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/auth/logout", methods=['POST'])
    @jwt_required()
    @require_active_session
    def logout():
        """User logout endpoint."""
        try:
            current_user_id = int(get_jwt_identity())
            session_token = request.headers.get('X-Session-Token')
            
            if session_token:
                # Remove specific session
                session = UserSession.query.filter_by(session_token=session_token).first()
                if session:
                    db.session.delete(session)
                    db.session.commit()
            
            log_authentication_event(
                user_id=current_user_id,
                action='LOGOUT',
                severity='INFO',
                details='User logged out successfully'
            )
            
            return jsonify({
                'message': 'Logout successful',
                'code': 'LOGOUT_SUCCESS'
            }), 200
            
        except Exception as e:
            log_authentication_event(
                action='LOGOUT_ERROR',
                severity='ERROR',
                details=f'Logout error: {str(e)}'
            )
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/auth/logout-all", methods=['POST'])
    @jwt_required()
    @require_active_session
    def logout_all():
        """Logout from all devices/sessions."""
        try:
            current_user_id = int(get_jwt_identity())
            
            # Revoke all user sessions
            revoked_count = revoke_user_sessions(current_user_id)
            
            log_authentication_event(
                user_id=current_user_id,
                action='LOGOUT_ALL',
                severity='INFO',
                details=f'User logged out from all devices ({revoked_count} sessions revoked)'
            )
            
            return jsonify({
                'message': f'Logged out from all devices ({revoked_count} sessions)',
                'code': 'LOGOUT_ALL_SUCCESS'
            }), 200
            
        except Exception as e:
            log_authentication_event(
                action='LOGOUT_ALL_ERROR',
                severity='ERROR',
                details=f'Logout all error: {str(e)}'
            )
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/auth/refresh-session", methods=['POST'])
    @jwt_required()
    @require_active_session
    def refresh_session():
        """Refresh user session to extend timeout."""
        try:
            current_user_id = int(get_jwt_identity())
            session_token = request.headers.get('X-Session-Token')
            
            if not session_token:
                return jsonify({'error': 'Session token required', 'code': 'MISSING_SESSION_TOKEN'}), 400
            
            session, error = validate_session(session_token)
            if error:
                log_authentication_event(
                    user_id=current_user_id,
                    action='SESSION_REFRESH_FAILED',
                    severity='WARN',
                    details=f'Session refresh failed: {error}'
                )
                return jsonify({'error': error, 'code': 'SESSION_INVALID'}), 401
            
            # Session is automatically updated by validate_session
            log_authentication_event(
                user_id=current_user_id,
                action='SESSION_REFRESHED',
                severity='INFO',
                details='User session refreshed successfully'
            )
            
            return jsonify({
                'message': 'Session refreshed successfully',
                'expires_at': session.expires_at.isoformat(),
                'code': 'SESSION_REFRESHED'
            }), 200
            
        except Exception as e:
            log_authentication_event(
                action='SESSION_REFRESH_ERROR',
                severity='ERROR',
                details=f'Session refresh error: {str(e)}'
            )
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/auth/profile", methods=['GET'])
    @jwt_required()
    @require_active_session
    def get_profile():
        """Get current user profile."""
        try:
            current_user_id = int(get_jwt_identity())
            user = User.query.get(current_user_id)
            
            if not user or not user.is_active:
                return jsonify({'error': 'User not found', 'code': 'USER_NOT_FOUND'}), 404
            
            log_access_event(
                user_id=current_user_id,
                action='PROFILE_ACCESS',
                resource='user_profile',
                details='User accessed their profile'
            )
            
            return jsonify({
                'user': user.to_dict(),
                'code': 'PROFILE_SUCCESS'
            }), 200
            
        except Exception as e:
            log_authentication_event(
                action='PROFILE_ERROR',
                severity='ERROR',
                details=f'Profile access error: {str(e)}'
            )
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500


# =================================================================
# === USER MANAGEMENT ROUTES (ADMIN ONLY) ===
# =================================================================

def register_user_management_routes(app):
    """Register user management routes for administrators."""
    
    @app.route("/api/admin/users", methods=['GET'])
    @jwt_required()
    @require_active_session
    @role_required(['administrator'])
    def get_all_users():
        """Get all users (admin only)."""
        try:
            users = User.query.all()
            users_data = [user.to_dict() for user in users]
            
            current_user_id = int(get_jwt_identity())
            log_access_event(
                user_id=current_user_id,
                action='VIEW_ALL_USERS',
                resource='user_management',
                details=f'Administrator viewed all users ({len(users)} users)'
            )
            
            return jsonify({
                'users': users_data,
                'count': len(users_data),
                'code': 'USERS_SUCCESS'
            }), 200
            
        except Exception as e:
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/admin/users", methods=['POST'])
    @jwt_required()
    @require_active_session
    @role_required(['administrator'])
    def create_user():
        """Create a new user (admin only)."""
        try:
            data = request.get_json()
            required_fields = ['email', 'password', 'role', 'first_name', 'last_name']
            
            if not data or not all(field in data for field in required_fields):
                return jsonify({'error': 'All fields are required', 'code': 'MISSING_FIELDS'}), 400
            
            # Check if user already exists
            existing_user = User.query.filter_by(email=data['email'].lower().strip()).first()
            if existing_user:
                return jsonify({'error': 'User with this email already exists', 'code': 'USER_EXISTS'}), 409
            
            # Validate role
            valid_roles = ['doctor', 'assistant', 'administrator']
            if data['role'] not in valid_roles:
                return jsonify({'error': 'Invalid role', 'code': 'INVALID_ROLE'}), 400
            
            # Create new user
            new_user = User(
                email=data['email'].lower().strip(),
                role=data['role'],
                first_name=data['first_name'],
                last_name=data['last_name'],
                is_active=data.get('is_active', True)
            )
            new_user.set_password(data['password'])
            
            db.session.add(new_user)
            db.session.commit()
            
            current_user_id = int(get_jwt_identity())
            log_access_event(
                user_id=current_user_id,
                action='CREATE_USER',
                resource='user_management',
                details=f'Administrator created user {new_user.email} with role {new_user.role}'
            )
            
            return jsonify({
                'message': 'User created successfully',
                'user': new_user.to_dict(),
                'code': 'USER_CREATED'
            }), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
    
    
    @app.route("/api/admin/users/<int:user_id>/assign-patient", methods=['POST'])
    @jwt_required()
    @require_active_session
    @role_required(['administrator'])
    def assign_patient_to_doctor_route(user_id):
        """Assign a patient to a doctor (admin only)."""
        try:
            data = request.get_json()
            if not data or 'patient_id' not in data:
                return jsonify({'error': 'Patient ID is required', 'code': 'MISSING_PATIENT_ID'}), 400
            
            patient_id = data['patient_id']
            success, message = assign_patient_to_doctor(user_id, patient_id)
            
            current_user_id = int(get_jwt_identity())
            
            if success:
                log_access_event(
                    user_id=current_user_id,
                    action='ASSIGN_PATIENT',
                    resource='patient_assignment',
                    details=f'Administrator assigned patient {patient_id} to doctor {user_id}'
                )
                return jsonify({'message': message, 'code': 'ASSIGNMENT_SUCCESS'}), 200
            else:
                log_access_event(
                    user_id=current_user_id,
                    action='ASSIGN_PATIENT_FAILED',
                    resource='patient_assignment',
                    details=f'Failed to assign patient {patient_id} to doctor {user_id}: {message}'
                )
                return jsonify({'error': message, 'code': 'ASSIGNMENT_FAILED'}), 400
            
        except Exception as e:
            return jsonify({'error': 'Internal server error', 'code': 'INTERNAL_ERROR'}), 500
