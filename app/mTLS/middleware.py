"""
mTLS Middleware for Flask with JWT fallback
Supports both mTLS and JWT authentication
CLEANED VERSION - Removed fake flow logging
"""

from flask import request, jsonify, current_app, g
from functools import wraps
import base64
from datetime import datetime
from app.logs.zta_event_logger import event_logger, EventType, Severity
import uuid
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def extract_client_certificate():
    """Extract client certificate from request"""
    cert_pem = None

    # Method 1: From SSL environment variable (for direct mTLS)
    if "SSL_CLIENT_CERT" in request.environ:
        cert_pem = request.environ["SSL_CLIENT_CERT"]

    # Method 2: From header (for proxy setups)
    elif "X-SSL-Client-Cert" in request.headers:
        cert_pem = request.headers["X-SSL-Client-Cert"]

    # Method 3: From custom header
    elif "X-Client-Certificate" in request.headers:
        cert_b64 = request.headers["X-Client-Certificate"]
        try:
            cert_pem = base64.b64decode(cert_b64).decode("utf-8")
        except:
            pass

    return cert_pem


def extract_public_key_from_cert(cert_pem):
    """Extract public key from certificate for encryption"""
    try:
        # Load certificate
        cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

        # Get public key
        public_key = cert.public_key()

        # Serialize to PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return public_pem.decode("utf-8")

    except Exception as e:
        current_app.logger.error(f"Failed to extract public key: {e}")
        return None


def no_auth_required(f):
    """Decorator that explicitly skips ALL authentication checks"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Bypass ALL authentication checks
        return f(*args, **kwargs)

    return decorated_function


def require_authentication(f=None, allow_unauthenticated=False):
    """
    Decorator that REQUIRES mTLS for ALL user endpoints
    """

    def decorator(func):
        @wraps(func)
        def decorated_function(*args, **kwargs):
            if allow_unauthenticated:
                return func(*args, **kwargs)

            # ============ ENFORCE mTLS - NO EXCEPTIONS ============
            cert_pem = extract_client_certificate()

            if not cert_pem:
                return (
                    jsonify(
                        {
                            "error": "mTLS Authentication Required",
                            "message": "This endpoint requires a valid client certificate",
                            "code": "MTLS_REQUIRED",
                        }
                    ),
                    401,
                )

            # Validate certificate with CRL
            from app.mTLS.cert_manager import cert_manager

            is_valid, result = cert_manager.validate_certificate_with_crl(
                cert_pem, enforce_crl=True
            )

            if not is_valid:
                return (
                    jsonify(
                        {
                            "error": "Invalid Client Certificate",
                            "message": str(result),
                            "code": "INVALID_CERTIFICATE",
                        }
                    ),
                    401,
                )

            cert_info = result

            # Check revocation (already done in validate_certificate_with_crl, but double-check)
            if cert_manager.is_certificate_revoked(cert_info.get("serial_number", "")):
                return (
                    jsonify(
                        {"error": "Certificate Revoked", "code": "CERTIFICATE_REVOKED"}
                    ),
                    401,
                )

            # Store certificate info
            g.client_certificate = cert_info
            g.auth_method = "mtls"

            # Extract user from certificate
            cert_email = cert_info.get("subject", {}).get("emailAddress", "")
            if cert_email:
                try:
                    from app.models.user import User

                    user = User.query.filter_by(email=cert_email).first()
                    if user:
                        g.current_user = user
                        g.jwt_identity = user.id  # For compatibility
                except Exception as e:
                    current_app.logger.error(f"User lookup failed: {e}")

            return func(*args, **kwargs)

        return decorated_function

    if f is None:
        return decorator
    return decorator(f)


def require_mtls(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Generate request ID
        request_id = str(uuid.uuid4())
        g.request_id = request_id

        cert_pem = extract_client_certificate()

        if not cert_pem:
            # Log certificate missing
            event_logger.log_event(  # CHANGED HERE
                event_type=EventType.CLIENT_CERT_INVALID,  # Use EventType enum
                source_component="mTLS",
                action="Certificate missing",
                details={
                    "reason": "No client certificate provided",
                    "endpoint": request.path,
                    "required": True,
                },
                status="failure",
                trace_id=request_id,
            )
            return (
                jsonify(
                    {
                        "error": "Client certificate required",
                        "code": "CERTIFICATE_REQUIRED",
                    }
                ),
                401,
            )

        # Use enhanced logging
        is_valid, cert_info_or_error = log_mtls_handshake(cert_pem, request_id)

        if not is_valid:
            return (
                jsonify(
                    {
                        "error": "Invalid client certificate",
                        "details": str(cert_info_or_error),
                        "code": "INVALID_CERTIFICATE",
                    }
                ),
                401,
            )

        # Certificate is valid
        cert_info = cert_info_or_error

        # Check if revoked
        from app.mTLS.cert_manager import cert_manager

        if cert_manager.is_certificate_revoked(cert_info.get("serial_number", "")):
            event_logger.log_event(  # CHANGED HERE
                event_type=EventType.CLIENT_CERT_INVALID,
                source_component="mTLS",
                action="Certificate revoked",
                details={
                    "serial": cert_info.get("serial_number"),
                    "fingerprint": cert_info.get("fingerprint", "")[:16] + "...",
                    "action": "access_denied",
                },
                status="failure",
                trace_id=request_id,
            )
            return (
                jsonify(
                    {
                        "error": "Certificate has been revoked",
                        "code": "CERTIFICATE_REVOKED",
                    }
                ),
                401,
            )

        # Extract and store public key
        public_key = extract_public_key_from_cert(cert_pem)
        if public_key:
            g.client_public_key = public_key

        # Log successful mTLS authentication
        event_logger.log_event(  # CHANGED HERE
            event_type=EventType.CLIENT_CERT_VALID,
            source_component="mTLS",
            action="Certificate validated",
            details={
                "fingerprint": cert_info.get("fingerprint", "")[:16] + "...",
                "subject": cert_info.get("subject", {}),
                "issuer": cert_info.get("issuer", {}),
                "valid_from": cert_info.get("not_valid_before"),
                "valid_to": cert_info.get("not_valid_after"),
                "validation_steps": [
                    "certificate_present",
                    "format_valid",
                    "not_expired",
                    "trusted_issuer",
                    "not_revoked",
                ],
            },
            status="success",
            trace_id=request_id,
        )

        # Add certificate info to Flask's g object
        g.client_certificate = cert_info
        g.auth_method = "mtls"

        return f(*args, **kwargs)

    return decorated_function


def require_jwt(f):
    """
    Decorator that requires JWT authentication (no mTLS fallback)
    Use for legacy endpoints or when mTLS isn't available
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

            verify_jwt_in_request()
            user_identity = get_jwt_identity()

            g.auth_method = "jwt"
            g.jwt_identity = user_identity

            # Try to get user's stored public key
            try:
                from app.models.user import User
                from app.mTLS.cert_manager import cert_manager

                user = User.query.get(user_identity)
                if user and user.public_key:
                    g.client_public_key = user.public_key
                elif user:
                    # Try to get from key storage
                    user_public_key = cert_manager.get_user_public_key(user_id=user.id)
                    if user_public_key:
                        g.client_public_key = user_public_key
            except:
                pass

            current_app.logger.info(
                f"JWT authentication required for user {user_identity}"
            )

            return f(*args, **kwargs)
        except Exception as e:
            return (
                jsonify({"error": "JWT token required or invalid", "details": str(e)}),
                401,
            )

    return decorated_function


def log_mtls_handshake(cert_pem, request_id=None):
    """Enhanced mTLS handshake logging with certificate details"""
    if not request_id:
        request_id = str(uuid.uuid4())

    try:
        from app.mTLS.cert_manager import cert_manager

        # Get client IP
        client_ip = None
        if request and hasattr(request, "remote_addr"):
            client_ip = request.remote_addr

        # Use enhanced validation with detailed logging
        is_valid, cert_info, validation_checks = (
            cert_manager.validate_certificate_with_detailed_logging(
                cert_pem, request_id, client_ip
            )
        )

        if is_valid:
            # Log certificate verification summary
            cert_manager.log_certificate_verification_summary(
                cert_pem, request_id, client_ip
            )

            # Extract subject for logging
            subject_email = cert_info.get("subject", {}).get("emailAddress", "Unknown")

            # Log successful handshake
            event_logger.log_event(  # CHANGED HERE
                event_type=EventType.MTLS_HANDSHAKE,
                source_component="mTLS",
                action="Handshake started",
                details={
                    "client": subject_email,
                    "client_ip": client_ip,
                    "certificate_fingerprint": cert_info.get("fingerprint", "")[:16]
                    + "...",
                    "validation_checks": validation_checks,
                },
                status="success",
                trace_id=request_id,
            )

        else:
            # Log failed handshake with detailed reason
            failed_checks = [k for k, v in validation_checks.items() if not v]
            event_logger.log_event(  # CHANGED HERE
                event_type=EventType.CLIENT_CERT_INVALID,
                source_component="mTLS",
                action="Certificate rejected",
                details={
                    "certificate_present": bool(cert_pem),
                    "failed_validation_checks": failed_checks,
                    "client_ip": client_ip,
                    "rejection_reason": "certificate_validation_failed",
                    "details": (
                        cert_info if isinstance(cert_info, str) else "multiple_failures"
                    ),
                },
                status="failure",
                trace_id=request_id,
            )

        return is_valid, cert_info if is_valid else None

    except Exception as e:
        event_logger.log_event(  # CHANGED HERE
            event_type=EventType.ERROR,
            source_component="mTLS",
            action="Handshake error",
            details={
                "error": str(e),
                "certificate_present": bool(cert_pem),
                "client_ip": client_ip,
            },
            status="failure",
            trace_id=request_id,
        )
        return False, str(e)
