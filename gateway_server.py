# gateway_server.py - UPDATED WITH CENTRALIZED SSL
"""
ZTA Gateway Server - Handles client authentication (mTLS + JWT)
Forwards authorized requests to API server
mTLS + HTTPS only - NO WebSockets
"""

from dotenv import load_dotenv

load_dotenv()

try:
    from app import ssl_patch  # This applies the Python 3.13 SSL fix

    print("✅ Applied SSL patch for Python 3.13")
except ImportError:
    print("⚠️ Could not import SSL patch")


import sys
import os
from flask import redirect, render_template, g
from app.mTLS.middleware import require_authentication
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.mTLS.conditional_mtls import require_mtls_for_api

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, g
import uuid
from datetime import datetime

from app.gateway_app import create_gateway_app

# Import centralized SSL config
try:
    from app.ssl_config import create_server_ssl_context

    HAS_SSL_CONFIG = True
except ImportError:
    HAS_SSL_CONFIG = False
    print("⚠️ Could not import create_server_ssl_context from ssl_config")

limiter = Limiter(key_func=get_remote_address)

app = create_gateway_app()

# Import real service communicator
from app.services.service_communicator import process_encrypted_request
from app.logs.zta_event_logger import event_logger, EventType, Severity
from app.logs.request_tracker import track_request_middleware

track_request_middleware(app)


@app.before_request
def generate_request_id():
    """Generate request ID for all requests"""
    g.request_id = str(uuid.uuid4())


@app.route("/api/opa-agent-public-key", methods=["GET"])
def public_opa_agent_key():
    """Public endpoint for OPA Agent public key - NO AUTH"""
    try:
        from app.opa_agent.client import get_opa_agent_client

        client = get_opa_agent_client()
        public_key = client.get_public_key()

        if not public_key:
            return jsonify({"error": "OPA Agent public key not available"}), 503

        return (
            jsonify(
                {
                    "public_key": public_key,
                    "algorithm": "RSA-OAEP-SHA256",
                    "key_size": 2048,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": f"Failed to get OPA Agent key: {str(e)}"}), 500


@app.route("/api/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE"])
def gateway_proxy(subpath):
    """
    Gateway endpoint - Use JWT for users, mTLS only for service-to-service
    """
    try:
        from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity

        # ============ PUBLIC ENDPOINTS (no auth) ============
        public_endpoints = [
            "auth/login",
            "auth/register",
            "health",
            "opa-agent-public-key",
        ]
        is_public = any(subpath.startswith(ep) for ep in public_endpoints)

        if is_public:
            result = process_encrypted_request(request, {})
            if isinstance(result, tuple):
                response_data, status_code = result
                return response_data, status_code
            return result

        # ============ USER ENDPOINTS (JWT authentication) ============
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()

            if not user_id:
                return jsonify({"error": "Invalid or expired token"}), 401

            from app.models.user import User

            user = User.query.get(user_id)

            if not user:
                return jsonify({"error": "User not found"}), 401

            user_claims = {
                "sub": user.id,
                "username": user.username,
                "email": user.email,
                "user_class": user.user_class,
                "facility": user.facility,
                "department": user.department,
                "clearance_level": user.clearance_level,
                "auth_method": "JWT",
            }

            # Process request with user claims
            result = process_encrypted_request(request, user_claims)

            if isinstance(result, tuple):
                response_data, status_code = result
                if hasattr(response_data, "json"):
                    try:
                        json_data = response_data.get_json()
                        if json_data and "encrypted_response" in json_data:
                            return response_data, status_code
                    except:
                        pass
                return result

            return result

        except Exception as jwt_error:
            return (
                jsonify(
                    {
                        "error": "Authentication required",
                        "message": "Valid JWT token required",
                        "code": "JWT_REQUIRED",
                    }
                ),
                401,
            )

    except Exception as e:
        return jsonify({"error": "Gateway processing failed", "message": str(e)}), 500


# Keep login page without mTLS
@app.route("/login")
def login_page():
    """Login page - no mTLS required"""
    return render_template("login.html")


@app.route("/resources/<int:resource_id>/view")
@require_authentication
def view_resource_page(resource_id):
    """
    View resource page - displays the resource after encryption flow
    """
    try:
        # Get current user from g (set by require_authentication middleware)
        user = g.current_user

        # Prepare user claims for OPA Agent
        user_claims = {
            "sub": user.id,
            "username": user.username,
            "email": user.email,
            "user_class": user.user_class,
            "facility": user.facility,
            "department": user.department,
            "clearance_level": user.clearance_level,
            "auth_method": getattr(g, "auth_method", "jwt"),
        }

        # Log the view request
        from app.logs.zta_event_logger import event_logger, EventType, Severity

        event_logger.log_event(
            event_type=EventType.REQUEST_RECEIVED,
            source_component="gateway",
            action=f"Resource view page requested - ID: {resource_id}",
            user_id=user.id,
            username=user.username,
            details={
                "resource_id": resource_id,
                "method": "GET",
                "endpoint": f"/resources/{resource_id}/view",
            },
            trace_id=g.request_id,
            severity=Severity.INFO,
        )

        # Render loader page (will use stored encrypted response)
        return render_template(
            "view_resource_loader.html",
            resource_id=resource_id,
            current_user=user,
            trace_id=g.request_id,
            user_claims=user_claims,
        )

    except Exception as e:
        return render_template(
            "error.html",
            error=f"Failed to load resource: {str(e)}",
            trace_id=getattr(g, "request_id", "unknown"),
        )


@app.route("/debug/cert-manager", methods=["GET"])
def debug_cert_manager():
    """Debug certificate manager state"""
    try:
        from app.mTLS.cert_manager import cert_manager

        # Check OPA Agent keys
        opa_dir = os.path.join(cert_manager.cert_dir, "opa_agent")
        opa_exists = os.path.exists(opa_dir)

        public_key = None
        if opa_exists:
            public_key_path = os.path.join(opa_dir, "public.pem")
            if os.path.exists(public_key_path):
                with open(public_key_path, "r") as f:
                    public_key = f.read()

        # Try to load via cert_manager
        loaded_key = cert_manager.load_opa_agent_public_key()

        return (
            jsonify(
                {
                    "opa_agent": {
                        "directory_exists": opa_exists,
                        "directory_path": opa_dir,
                        "public_key_file_exists": (
                            os.path.exists(os.path.join(opa_dir, "public.pem"))
                            if opa_exists
                            else False
                        ),
                        "public_key_loaded": bool(loaded_key),
                        "loaded_key_length": len(loaded_key) if loaded_key else 0,
                        "loaded_key_valid": (
                            loaded_key
                            and loaded_key.startswith("-----BEGIN PUBLIC KEY-----")
                            if loaded_key
                            else False
                        ),
                        "loaded_key_preview": (
                            loaded_key[:200] + "..." if loaded_key else None
                        ),
                        "manual_key_length": len(public_key) if public_key else 0,
                        "manual_key_valid": (
                            public_key
                            and public_key.startswith("-----BEGIN PUBLIC KEY-----")
                            if public_key
                            else False
                        ),
                    }
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Keep some direct endpoints for testing
@app.route("/api/zta-test", methods=["GET"])
def zta_test():
    """Simple test endpoint"""
    return jsonify(
        {
            "status": "success",
            "message": "Gateway server is running",
            "server": "gateway",
        }
    )


@app.route("/debug/opa-key", methods=["GET"])
def debug_opa_key():
    """Debug OPA Agent public key"""
    try:
        from app.opa_agent.client import get_opa_agent_client

        client = get_opa_agent_client()
        agent_public_key = (
            client.agent_public_key
        )  # Changed from public_key to agent_public_key

        # Also check via cert_manager directly
        from app.mTLS.cert_manager import cert_manager

        cert_manager_key = cert_manager.load_opa_agent_public_key()

        return (
            jsonify(
                {
                    "client_key_loaded": bool(agent_public_key),
                    "client_key_length": (
                        len(agent_public_key) if agent_public_key else 0
                    ),
                    "client_key_valid": (
                        agent_public_key
                        and agent_public_key.startswith("-----BEGIN PUBLIC KEY-----")
                        if agent_public_key
                        else False
                    ),
                    "client_key_preview": (
                        agent_public_key[:100] + "..." if agent_public_key else None
                    ),
                    "cert_manager_key_loaded": bool(cert_manager_key),
                    "cert_manager_key_length": (
                        len(cert_manager_key) if cert_manager_key else 0
                    ),
                    "cert_manager_key_valid": (
                        cert_manager_key
                        and cert_manager_key.startswith("-----BEGIN PUBLIC KEY-----")
                        if cert_manager_key
                        else False
                    ),
                    "opa_agent_client": str(client),
                    "session_created": bool(client.session),
                }
            ),
            200,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
@limiter.limit("10 per minute")
def health():
    """Health check"""
    return jsonify(
        {
            "status": "healthy",
            "server": "gateway",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


if __name__ == "__main__":
    print("=" * 60)
    print("ZTA GATEWAY SERVER (mTLS + HTTPS)")
    print("=" * 60)
    print(f"Port: 5000")
    print("Authentication: mTLS + JWT")
    print("Dashboard: https://localhost:5002")
    print("=" * 60)

    # Setup SSL context using centralized config
    if HAS_SSL_CONFIG:

        # CERT_OPTIONAL allows login without certificate
        # But our decorator will enforce mTLS for API endpoints
        context = create_server_ssl_context(
            verify_client=True,  # Request certificate if available
            require_mtls=False,  # Don't REQUIRE it for connection
        )
    else:
        import ssl

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain("certs/server.crt", "certs/server.key")
        context.load_verify_locations("certs/ca.crt")
        context.verify_mode = ssl.CERT_OPTIONAL  # ← Request but don't require
        context.check_hostname = False

    # ============ ADD PRE-WARMING ============
    import threading
    import time

    def prewarm_connections():
        """Pre-establish SSL connections to all services"""
        time.sleep(2)  # Wait for servers to start
        try:
            from app.ssl_fix import get_ssl_fixed_session

            session = get_ssl_fixed_session()

            services = [
                ("https://localhost:8282/health", "OPA Agent"),
                ("https://localhost:5001/health", "API Server"),
                ("https://localhost:8181/health", "OPA Server"),
            ]

            for url, name in services:
                try:
                    start = time.time()
                    response = session.get(url, timeout=5)
                    elapsed = (time.time() - start) * 1000
                    if response.status_code == 200:
                        print(f"✅ Pre-warmed: {name} ({elapsed:.0f}ms)")
                    else:
                        print(f"⚠️ Pre-warm: {name} returned {response.status_code}")
                except Exception as e:
                    print(f"⚠️ Pre-warm failed for {name}: {e}")
        except Exception as e:
            print(f"⚠️ Pre-warm error: {e}")

    # Start pre-warming thread
    threading.Thread(target=prewarm_connections, daemon=True).start()
    # ============ END PRE-WARMING ============
    # Run with proper SSL + mTLS
    # app.run(host="127.0.0.1", port=5000, ssl_context=context, debug=True)

    # for testing with external access, use
    app.run(host="0.0.0.0", port=5000, ssl_context=context, debug=True)
