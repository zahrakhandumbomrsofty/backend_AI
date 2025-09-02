# Authentication & Authorization Guide

This document describes the authentication and authorization system implemented in the backend (`auth.py`, `auth_routes.py`) and how the frontend integrates with it.

## Overview

- Two-step login with email/password and MFA code (sent via email).
- JWT used for API authorization.
- Separate server-side session tracking via `UserSession` with timeout/refresh.
- Role- and resource-based access controls with audit logging to DB and S3.

## Key Modules

- `auth.py`: Core services and helpers.
  - JWT error handlers (expired/invalid/missing).
  - Session helpers: create/validate/extend/revoke.
  - MFA helpers: create/validate/send email.
  - Audit logging to DB and S3.
  - Authorization decorators: `role_required`, `patient_access_required`, `log_access`.
- `auth_routes.py`: HTTP endpoints that expose the auth flows and admin user management.

## Endpoints (auth_routes.py)
Base path: `/api`

- POST `/auth/login`
  - Body: `{ email, password }`
  - Returns: `{ user_id, mfa_required: true, code: 'MFA_REQUIRED' }`
  - Side effects: Generates MFA code and emails it to the user.

- POST `/auth/verify-mfa`
  - Body: `{ user_id, mfa_code }`
  - Returns: `{ access_token, session_token, user, expires_at, code: 'AUTH_SUCCESS' }`
  - Side effects: Marks MFA code as used, creates JWT and a `UserSession`.

- POST `/auth/resend-mfa`
  - Body: `{ user_id }`
  - Returns: `{ message, code: 'MFA_RESENT' }`

- POST `/auth/logout` (JWT required)
  - Headers: `Authorization: Bearer <access_token>`, optional `X-Session-Token`
  - Returns: `{ message, code: 'LOGOUT_SUCCESS' }`

- POST `/auth/logout-all` (JWT required)
  - Headers: `Authorization: Bearer <access_token>`
  - Returns: `{ message, code: 'LOGOUT_ALL_SUCCESS' }`

- POST `/auth/refresh-session` (JWT required)
  - Headers: `Authorization: Bearer <access_token>`, `X-Session-Token`
  - Returns: `{ message, expires_at, code: 'SESSION_REFRESHED' }`

- GET `/auth/profile` (JWT required)
  - Headers: `Authorization: Bearer <access_token>`
  - Returns: `{ user, code: 'PROFILE_SUCCESS' }`

### Admin-only user management (requires JWT and `administrator` role)

- GET `/admin/users`
  - Returns: `{ users: [...], count, code: 'USERS_SUCCESS' }`

- POST `/admin/users`
  - Body: `{ email, password, role, first_name, last_name, is_active? }`
  - Returns: `{ message, user, code: 'USER_CREATED' }`

- POST `/admin/users/<user_id>/assign-patient`
  - Body: `{ patient_id }`
  - Returns: `{ message|error, code }`

## auth.py Functionalities

- JWT configuration and error handlers:
  - `expired_token_callback`, `invalid_token_callback`, `missing_token_callback` → standardized 401 errors and audit logs.

- Session management:
  - `create_user_session(user_id, expires_in_minutes)`: Creates `UserSession` with IP/User-Agent.
  - `validate_session(session_token)`: Validates and updates activity, purges expired.
  - `check_session_timeout()`: Soft gate using `X-Session-Token`.
  - `extend_session(session_token)`: Extends expiry and updates activity.
  - `revoke_user_sessions(user_id)`: Deletes all sessions for a user.

- MFA:
  - `create_mfa_code(user_id)`: Invalidates prior unused codes, creates a new one with expiry.
  - `validate_mfa_code(user_id, code)`: Verifies and marks as used.
  - `send_mfa_code_email(user, mfa_code)`: Sends HTML email via Flask-Mail.

- Authorization decorators:
  - `role_required(allowed_roles)`: Ensures JWT, active user, and role membership.
  - `patient_access_required`: Ensures current user can access a specific `patient_id`.
  - `log_access`: Logs access for decorated routes.

- Audit logging:
  - `log_authentication_event` / `log_access_event`: Persist to DB (`AuditLog`) and upload to S3 (`send_audit_log_to_s3`).

## Tokens and Sessions

- JWT (`access_token`) is required in `Authorization: Bearer <token>` header for protected endpoints.
- Server session (`session_token`) is created at MFA verification and should be sent as `X-Session-Token` for session refresh and logout.
- Default timeouts: session = 30 minutes of inactivity; MFA code = 10 minutes.

## Error Codes (examples)

- `TOKEN_EXPIRED`, `INVALID_TOKEN`, `MISSING_TOKEN`
- `MISSING_CREDENTIALS`, `INVALID_CREDENTIALS`, `ACCOUNT_INACTIVE`
- `MISSING_MFA_DATA`, `INVALID_MFA_CODE`, `MFA_SEND_FAILED`
- `MISSING_SESSION_TOKEN`, `SESSION_INVALID`
- `USER_NOT_FOUND`, `INSUFFICIENT_PERMISSIONS`, `PATIENT_ACCESS_DENIED`

## Environment Variables and Config

- Mail: `MAIL_DEFAULT_SENDER` (and standard Flask-Mail settings)
- AWS/S3: `AUDIT_LOG_BUCKET` (default `medical-app-audit-logs`), `AWS_REGION` (default `us-east-1`)
- Timeouts: `SESSION_TIMEOUT_MINUTES`, `MFA_CODE_EXPIRATION_MINUTES` (constants in `auth.py`)

## Frontend Integration (React example)

- Step 1: Login
  - POST `/api/auth/login` with `{ email, password }` → receive `{ user_id, mfa_required: true }`.
- Step 2: Verify MFA
  - POST `/api/auth/verify-mfa` with `{ user_id, mfa_code }` → receive `{ access_token, session_token }`.
  - Store tokens (e.g., `localStorage`) and include:
    - `Authorization: Bearer <access_token>`
    - `X-Session-Token: <session_token>` when required.

Example minimal flow using axios:
```js
// Login
await axios.post('/api/auth/login', { email, password });
// Verify
const { data } = await axios.post('/api/auth/verify-mfa', { user_id, mfa_code });
localStorage.setItem('accessToken', data.access_token);
localStorage.setItem('sessionToken', data.session_token);
```

## cURL Examples

```bash
# Login
curl -X POST \
  -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"secret"}' \
  http://localhost:5000/api/auth/login

# Verify MFA
curl -X POST \
  -H 'Content-Type: application/json' \
  -d '{"user_id":1,"mfa_code":"123456"}' \
  http://localhost:5000/api/auth/verify-mfa

# Profile (JWT required)
curl -H 'Authorization: Bearer <ACCESS_TOKEN>' \
  http://localhost:5000/api/auth/profile

# Refresh session (JWT + Session token)
curl -X POST \
  -H 'Authorization: Bearer <ACCESS_TOKEN>' \
  -H 'X-Session-Token: <SESSION_TOKEN>' \
  http://localhost:5000/api/auth/refresh-session
```

## Notes

- All protected routes require a valid JWT; some require the `X-Session-Token` header.
- Admin endpoints additionally require the `administrator` role.
- Audit logs are stored both in the database and in S3 in a syslog-like format.
