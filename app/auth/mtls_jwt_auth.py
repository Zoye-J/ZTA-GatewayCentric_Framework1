"""
Unified Authentication: JWT + mTLS + OPA
For Zero Trust Architecture
"""

from flask import request, jsonify, current_app
from app.logs.zta_event_logger import event_logger, EventType, Severity
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
import hashlib
from cryptography import x509
from datetime import datetime
from cryptography.hazmat.backends import default_backend
import json


class ZeroTrustAuthenticator:
    """Handles JWT + mTLS + OPA authentication"""

    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app"""
        self.app = app

    def extract_certificate(self):
        """Extract and validate client certificate"""
        cert_pem = request.environ.get("SSL_CLIENT_CERT")

        if not cert_pem:
            return None

        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            fingerprint = cert.fingerprint(hashlib.sha256()).hex()

            # Extract identity info
            identity = {
                "fingerprint": fingerprint,
                "serial": format(cert.serial_number, "X"),
                "subject": {},
                "email": None,
                "department": None,
                "type": None,  # 'user' or 'service'
            }

            # Parse subject
            for attr in cert.subject:
                identity["subject"][attr.oid._name] = attr.value

                if attr.oid._name == "emailAddress":
                    identity["email"] = attr.value
                    identity["type"] = "user"
                elif attr.oid._name == "commonName":
                    if "@" in attr.value:
                        identity["email"] = attr.value
                        identity["type"] = "user"
                    else:
                        identity["service_name"] = attr.value
                        identity["type"] = "service"
                elif attr.oid._name == "organizationName":
                    identity["department"] = attr.value

            return identity

        except Exception as e:
            current_app.logger.error(f"Certificate error: {e}")
            return None

    class ZeroTrustAuthenticator:
        """Handles JWT + mTLS binding for Zero Trust"""

        def authenticate_request(self, require_binding=True):
            """
            Authenticate request with STRONG binding between JWT and mTLS

            Args:
                require_binding: If True, JWT and mTLS must match exactly
            """
            cert_identity = self.extract_certificate()

            if not cert_identity:
                return False, None, None, "mTLS certificate required"

            # Service-to-service: only mTLS needed
            if cert_identity["type"] == "service":
                return True, cert_identity, "mTLS_service", None

            # User request: REQUIRE JWT
            try:
                verify_jwt_in_request()  # ← No optional
                jwt_user_id = get_jwt_identity()

                from app.models.user import User

                user = User.query.get(jwt_user_id)

                if not user:
                    return False, None, None, "JWT user not found"

                # ============ STRONG BINDING ============
                # Check 1: Email must match certificate
                if require_binding and user.email != cert_identity.get("email"):
                    self._log_binding_failure(user.email, cert_identity.get("email"))
                    return (
                        False,
                        None,
                        None,
                        "JWT email does not match certificate email",
                    )

                # Check 2: Certificate must be issued to this user
                stored_fingerprint = user.certificate_fingerprint
                if stored_fingerprint and stored_fingerprint != cert_identity.get(
                    "fingerprint"
                ):
                    self._log_binding_failure("fingerprint mismatch", "")
                    return False, None, None, "Certificate fingerprint mismatch"

                # Check 3: JWT must have been issued after certificate was issued
                # (Prevents using old JWT with new certificate)
                jwt_claims = get_jwt()
                jwt_issued_at = jwt_claims.get("iat", 0)
                cert_issued_at = cert_identity.get("not_valid_before_timestamp", 0)

                if jwt_issued_at < cert_issued_at:
                    return (
                        False,
                        None,
                        None,
                        "JWT issued before certificate - possible replay attack",
                    )

                # All checks passed
                return (
                    True,
                    {**cert_identity, "user_id": jwt_user_id, "user": user},
                    "mTLS_JWT_BOUND",
                    None,
                )

            except Exception as e:
                return False, None, None, f"JWT required: {str(e)}"

        def _log_binding_failure(self, expected, actual):
            """Log binding failures for audit"""
            event_logger.log_event(
                event_type=EventType.SECURITY_VIOLATION,
                source_component="zta_auth",
                action="JWT-mTLS binding failed",
                details={"expected": expected, "actual": actual},
                severity=Severity.HIGH,
            )

    def require_zta_auth(self, require_jwt_for_users=True):
        """
        Decorator for Zero Trust Authentication
        require_jwt_for_users: True = users need JWT+mTLS, False = services only need mTLS
        """

        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                authenticated, identity, auth_method, error = (
                    self.authenticate_request()
                )

                if not authenticated:
                    return (
                        jsonify(
                            {
                                "error": "Zero Trust Authentication failed",
                                "message": error,
                                "required": "mTLS"
                                + (" + JWT" if require_jwt_for_users else ""),
                                "hint": "For users: JWT token + client certificate\nFor services: Client certificate only",
                            }
                        ),
                        401,
                    )

                # Add authentication info to request
                request.zta_identity = identity
                request.zta_auth_method = auth_method

                # Log the authentication
                current_app.logger.info(
                    f"ZTA Auth: {auth_method} - {identity.get('email', identity.get('service_name', 'unknown'))}"
                )

                return f(*args, **kwargs)

            return decorated_function

        return decorator

    def check_opa_policy(self, resource, action, identity):
        """Check OPA policy for this request"""
        try:
            from app.policy.opa_client import opa_client

            # Prepare input for OPA
            input_data = {
                "input": {
                    "identity": identity,
                    "resource": resource,
                    "action": action,
                    "timestamp": datetime.utcnow().isoformat(),
                    "auth_method": getattr(request, "zta_auth_method", "unknown"),
                }
            }

            # Query OPA
            result = opa_client.check_policy("zta/main", input_data)

            if result.get("result", {}).get("allow", False):
                return True, result.get("result", {}).get("reason", "Allowed by policy")
            else:
                return False, result.get("result", {}).get("reason", "Denied by policy")

        except Exception as e:
            current_app.logger.error(f"OPA error: {e}")
            return False, f"Policy evaluation failed: {e}"


# Singleton instance
zta_auth = ZeroTrustAuthenticator()
