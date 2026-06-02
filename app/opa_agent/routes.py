"""
OPA Agent Routes for Gateway Server
Exposes OPA Agent endpoints through Gateway
"""

from datetime import datetime
from app.logs.zta_event_logger import event_logger, EventType, Severity
import uuid
from flask import Blueprint, jsonify, current_app, request
from functools import wraps
from datetime import datetime
import uuid
import os

opa_agent_bp = Blueprint("opa_agent", __name__)


def require_service_token(f):
    """Require valid service token for internal endpoints"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        service_token = request.headers.get("X-Service-Token")
        expected_token = current_app.config.get("OPA_AGENT_TOKEN")

        if not service_token or service_token != expected_token:
            # Also check if it's a localhost request (for development)
            if request.remote_addr not in ["127.0.0.1", "localhost"]:
                return (
                    jsonify({"error": "Unauthorized - valid service token required"}),
                    401,
                )

        return f(*args, **kwargs)

    return decorated_function


opa_agent_bp = Blueprint("opa_agent", __name__)


@opa_agent_bp.route("/health", methods=["GET"])
@require_service_token
def opa_agent_health():
    """OPA Agent health check endpoint"""
    try:
        from app.opa_agent.client import get_opa_agent_client

        client = get_opa_agent_client()
        # Log health check access
        event_logger.log_event(
            event_type=EventType.HEALTH_CHECK,
            source_component="gateway",
            action="Health check accessed",
            details={"source_ip": request.remote_addr},
            severity=Severity.INFO,
        )

        if not client:
            return (
                jsonify(
                    {
                        "status": "unavailable",
                        "service": "OPA Agent Client",
                        "message": "Client not initialized",
                    }
                ),
                503,
            )

        is_healthy = client.health_check()

        return jsonify(
            {
                "status": "healthy" if is_healthy else "unhealthy",
                "service": "OPA Agent Gateway Integration",
                "timestamp": datetime.utcnow().isoformat(),
                "agent_url": (
                    client.agent_url if hasattr(client, "agent_url") else "unknown"
                ),
                "public_key_available": (
                    bool(client.get_public_key())
                    if hasattr(client, "get_public_key")
                    else False
                ),
            }
        ), (200 if is_healthy else 503)

    except Exception as e:
        return (
            jsonify(
                {
                    "status": "error",
                    "service": "OPA Agent Health Check",
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            500,
        )


@opa_agent_bp.route("/public-key", methods=["GET"])
@require_service_token
def get_opa_agent_public_key():
    """Get OPA Agent's public key"""
    try:
        from app.opa_agent.client import get_opa_agent_client

        client = get_opa_agent_client()

        if not client:
            return jsonify({"error": "OPA Agent client not available"}), 503

        public_key = client.get_public_key()

        if not public_key:
            return jsonify({"error": "OPA Agent public key not available"}), 503

        return (
            jsonify(
                {
                    "public_key": public_key,
                    "algorithm": "RSA-OAEP-SHA256",
                    "key_size": 2048,
                    "format": "PEM",
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "gateway_proxy",
                }
            ),
            200,
        )

    except Exception as e:
        return (
            jsonify({"error": "Failed to get OPA Agent public key", "message": str(e)}),
            500,
        )


@opa_agent_bp.route("/status", methods=["GET"])
@require_service_token
def opa_agent_status():
    """Get detailed OPA Agent status"""
    try:
        from app.opa_agent.client import get_opa_agent_client
        import requests

        client = get_opa_agent_client()

        status = {
            "gateway_integration": {
                "client_initialized": bool(client),
                "has_public_key": bool(client.get_public_key()) if client else False,
            },
            "direct_agent_status": "unknown",
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Try to contact OPA Agent directly
        if client and hasattr(client, "agent_url"):
            try:
                response = requests.get(f"{client.agent_url}/health", timeout=3)
                status["direct_agent_status"] = {
                    "status_code": response.status_code,
                    "healthy": response.status_code == 200,
                    "response": (
                        response.json() if response.status_code == 200 else None
                    ),
                }
            except Exception as e:
                status["direct_agent_status"] = {"error": str(e), "healthy": False}

        return jsonify(status), 200

    except Exception as e:
        return (
            jsonify({"error": "Failed to get OPA Agent status", "message": str(e)}),
            500,
        )


@opa_agent_bp.route("/encrypt-test", methods=["POST"])
@require_service_token
def encrypt_test():
    """Test encryption with OPA Agent"""
    try:
        from app.opa_agent.client import get_opa_agent_client

        client = get_opa_agent_client()

        if not client:
            return jsonify({"error": "OPA Agent client not available"}), 503

        # Test data
        test_data = {
            "message": "Test encryption from Gateway",
            "timestamp": datetime.utcnow().isoformat(),
            "test_id": str(uuid.uuid4())[:8],
        }

        # Try to encrypt
        encrypted = client.encrypt_for_agent(test_data)

        return (
            jsonify(
                {
                    "test": "encryption_test",
                    "original_data": test_data,
                    "encrypted": (
                        encrypted[:100] + "..." if len(encrypted) > 100 else encrypted
                    ),
                    "encrypted_length": len(encrypted),
                    "status": "success",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Encryption test failed", "message": str(e)}), 500
