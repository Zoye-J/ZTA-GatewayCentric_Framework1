"""
Conditional mTLS Enforcement
Different requirements for different endpoints
"""

from flask import request, jsonify, g
from functools import wraps
from app.mTLS.middleware import extract_client_certificate
from app.mTLS.cert_manager import cert_manager
from app.logs.zta_event_logger import event_logger, EventType, Severity


def require_mtls_for_api(f):
    """
    Require mTLS for API endpoints, but allow login without cert
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # List of public endpoints that don't require mTLS
        public_endpoints = [
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh",
            "/health",
            "/api/opa-agent-public-key",
            "/login",
            "/register",
        ]

        # Check if current path is public
        is_public = any(
            request.path.startswith(endpoint) for endpoint in public_endpoints
        )

        if is_public:
            # Public endpoint - no mTLS required
            return f(*args, **kwargs)

        # API endpoint - REQUIRE mTLS
        cert_pem = extract_client_certificate()

        if not cert_pem:
            event_logger.log_event(
                event_type=EventType.SECURITY_VIOLATION,
                source_component="gateway",
                action="mTLS required but no certificate",
                details={"endpoint": request.path, "ip": request.remote_addr},
                severity=Severity.HIGH,
            )
            return (
                jsonify(
                    {
                        "error": "mTLS Authentication Required",
                        "message": "This API endpoint requires a valid client certificate",
                        "code": "MTLS_REQUIRED",
                    }
                ),
                401,
            )

        # Validate certificate with CRL
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
                    g.jwt_identity = user.id
            except Exception as e:
                pass

        return f(*args, **kwargs)

    return decorated_function
