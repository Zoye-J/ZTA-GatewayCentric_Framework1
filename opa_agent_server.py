"""
OPA Agent Server with Encryption - FIXED VERSION
Runs on Port 8282
Uses centralized SSL config
"""

from dotenv import load_dotenv

load_dotenv()
from flask import Flask, request, jsonify, g
from app.opa_agent.agent import OpaAgent
import uuid
import os
import logging
import ssl
from app.logs.zta_event_logger import event_logger, EventType, Severity
import json
from functools import wraps

# Import centralized SSL config
try:
    from app.ssl_config import create_opa_agent_ssl_context

    HAS_SSL_CONFIG = True
except ImportError:
    HAS_SSL_CONFIG = False


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def create_opa_agent_app():
    """Create OPA Agent Flask application"""
    app = Flask(__name__)  # ← CHANGE: Use 'app' consistently
    agent = OpaAgent()

    # Get service tokens from config
    GATEWAY_SERVICE_TOKEN = os.environ.get(
        "GATEWAY_SERVICE_TOKEN", "gateway-token-2024-zta"
    )

    @app.before_request
    def setup_request():
        """Setup request context"""
        g.request_id = str(uuid.uuid4())
        g.agent = agent

    @app.before_request
    def block_direct_access():
        """Block all requests not coming from Gateway"""

        # Only Gateway should call OPA Agent
        allowed_tokens = [GATEWAY_SERVICE_TOKEN]

        # Health endpoint - restrict to localhost only
        if request.path == "/health":
            # Only allow from localhost or with service token
            if request.remote_addr in ["127.0.0.1", "::1"]:
                return None

            service_token = request.headers.get("X-Service-Token")
            if service_token and service_token in allowed_tokens:
                return None

            print(f"[SECURITY] Blocked health check from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 401

        # Public key endpoint - restrict to Gateway only
        if request.path == "/public-key":
            service_token = request.headers.get("X-Service-Token")
            if not service_token or service_token not in allowed_tokens:
                print(
                    f"[SECURITY] Blocked public-key access from {request.remote_addr}"
                )
                return jsonify({"error": "Unauthorized - Gateway only"}), 401
            return None

        # Evaluate endpoint - Gateway only
        if request.path == "/evaluate":
            service_token = request.headers.get("X-Service-Token")
            if not service_token or service_token not in allowed_tokens:
                print(f"[SECURITY] Blocked evaluate access from {request.remote_addr}")
                return jsonify({"error": "Unauthorized - Gateway only"}), 401
            return None

        # Block all other direct access
        print(
            f"[SECURITY] Blocked direct access to {request.path} from {request.remote_addr}"
        )
        return jsonify({"error": "Access Denied - Use ZTA Gateway"}), 403

    # Note: The decorator below is not used because middleware handles auth
    # Keeping it for reference but not applying to routes

    @app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint - requires service token or localhost"""
        # Check if from localhost
        if request.remote_addr in ["127.0.0.1", "::1"]:
            return (
                jsonify(
                    {
                        "status": "healthy",
                        "service": "OPA Agent",
                        "port": 8282,
                        "encryption": "RSA-2048",
                        "public_key_available": bool(agent.get_public_key()),
                    }
                ),
                200,
            )

        # Check service token
        service_token = request.headers.get("X-Service-Token")
        expected_token = os.environ.get(
            "GATEWAY_SERVICE_TOKEN", "gateway-token-2024-zta"
        )

        if service_token and service_token == expected_token:
            return (
                jsonify(
                    {
                        "status": "healthy",
                        "service": "OPA Agent",
                        "port": 8282,
                        "encryption": "RSA-2048",
                        "public_key_available": bool(agent.get_public_key()),
                    }
                ),
                200,
            )

        # Block all others
        print(f"[SECURITY] Unauthorized health check from {request.remote_addr}")
        return jsonify({"error": "Unauthorized"}), 401

    @app.route("/evaluate", methods=["POST"])
    def evaluate():
        """
        Main endpoint: Receive encrypted request, process, return encrypted response

        Expected payload:
        {
            "encrypted_request": "base64_encrypted_data",
            "user_public_key": "PEM_public_key",
            "request_id": "optional_id"
        }
        """
        trace_id = None  # Initialize for error handling
        try:
            data = request.json
            request_id = data.get("request_id", g.request_id)

            # Get trace ID from headers or generate
            trace_id = request.headers.get(
                "X-Trace-ID", f"opa_{int(uuid.uuid4().int % 1000000)}"
            )

            logger.info(f"[{request_id}] OPA Agent received request")

            # DEBUG: Log what we received
            logger.info(
                f"[{request_id}] Encrypted data length: {len(data.get('encrypted_request', ''))}"
            )
            logger.info(
                f"[{request_id}] User public key present: {'yes' if 'user_public_key' in data else 'no'}"
            )

            # Step 1: Decrypt request with agent's private key
            encrypted_request = data["encrypted_request"]

            # DEBUG: Show first 100 chars of encrypted data
            logger.info(
                f"[{request_id}] Encrypted data (first 100): {encrypted_request[:100]}"
            )

            # Log when OPA Agent receives request
            event_logger.log_event(
                event_type=EventType.REQUEST_RECEIVED,
                source_component="opa_agent",
                action="Received encrypted request from gateway",
                trace_id=trace_id,
                details={
                    "request_id": request_id,
                    "encrypted": True,
                    "endpoint": "/evaluate",
                },
                severity=Severity.INFO,
            )

            # Log before decryption
            event_logger.log_event(
                event_type=EventType.REQUEST_DECRYPTED,
                source_component="opa_agent",
                action="Decrypting request with RSA private key",
                trace_id=trace_id,
                details={
                    "request_id": request_id,
                    "encryption": "RSA-OAEP-SHA256",
                    "key_size": 2048,
                },
                severity=Severity.INFO,
            )

            decrypted_data = agent.decrypt_request(encrypted_request)

            # Log successful decryption
            event_logger.log_event(
                event_type=EventType.REQUEST_DECRYPTED,
                source_component="opa_agent",
                action="Successfully decrypted request",
                trace_id=trace_id,
                details={
                    "request_id": request_id,
                    "status": "success",
                    "data_length": len(decrypted_data),
                },
                severity=Severity.INFO,
            )

            # Step 2: Parse decrypted data
            request_info = json.loads(decrypted_data)

            # Log parsed request info
            event_logger.log_event(
                event_type=EventType.OPA_REQUEST_SENT,
                source_component="opa_agent",
                action="Parsed decrypted request",
                trace_id=trace_id,
                details={
                    "request_id": request_id,
                    "method": request_info.get("method", "Unknown"),
                    "path": request_info.get(
                        "endpoint", "Unknown"
                    ),  # ← FIXED: use "endpoint"
                    "user_id": request_info.get("user", {}).get("id", "Unknown"),
                },
                severity=Severity.INFO,
            )

            # Step 3: Forward to OPA Server for policy evaluation
            opa_result = agent.query_opa_server(request_info)

            # Log OPA response
            event_logger.log_event(
                event_type=EventType.OPA_RESPONSE_RECEIVED,
                source_component="opa_agent",
                action="Received policy decision from OPA Server",
                trace_id=trace_id,
                details={
                    "request_id": request_id,
                    "allowed": opa_result.get("result", False),
                    "reason": opa_result.get("reason", "No reason provided"),
                },
                severity=Severity.INFO,
            )

            # Step 4: Check if access is allowed
            if not opa_result.get("result", False):
                # Access denied - still encrypt response
                response_data = {
                    "allowed": False,
                    "reason": opa_result.get("reason", "Access denied by policy"),
                    "opa_result": opa_result,
                }

                # Log policy denial
                event_logger.log_event(
                    event_type=EventType.POLICY_DENY,
                    source_component="opa_agent",
                    action=f"Access DENIED by policy",
                    trace_id=trace_id,
                    user_id=request_info.get("user", {}).get("id"),
                    username=request_info.get("user", {}).get("username"),
                    details={
                        "request_id": request_id,
                        "reason": opa_result.get("reason", "Access denied"),
                        "resource": request_info.get("endpoint"),
                    },
                    severity=Severity.MEDIUM,
                )
            else:
                # Access allowed - call API Server
                logger.info(f"[{request_id}] Access allowed, calling API Server")

                # Log policy allowance
                event_logger.log_event(
                    event_type=EventType.POLICY_ALLOW,
                    source_component="opa_agent",
                    action=f"Access ALLOWED by policy",
                    trace_id=trace_id,
                    user_id=request_info.get("user", {}).get("id"),
                    username=request_info.get("user", {}).get("username"),
                    details={
                        "request_id": request_id,
                        "resource": request_info.get("endpoint"),
                    },
                    severity=Severity.INFO,
                )

                # Extract API call info from request
                event_logger.log_event(
                    event_type=EventType.API_REQUEST,
                    source_component="opa_agent",
                    action="Forwarding to API Server",
                    trace_id=trace_id,
                    user_id=request_info.get("user", {}).get("id"),
                    details={
                        "request_id": request_id,
                        "api_server_url": "https://localhost:5001",
                        "method": request_info.get("method"),
                        "path": request_info.get("endpoint"),
                    },
                    severity=Severity.INFO,
                )

                api_response = agent.call_api_server(request_info)

                # Log API response
                event_logger.log_event(
                    event_type=EventType.API_RESPONSE,
                    source_component="opa_agent",
                    action="Received response from API Server",
                    trace_id=trace_id,
                    details={
                        "request_id": request_id,
                        "response_status": (
                            "success" if api_response.get("success") else "error"
                        ),
                    },
                    severity=Severity.INFO,
                )

                response_data = {
                    "allowed": True,
                    "api_response": api_response,
                    "opa_result": opa_result,
                }

            # Step 5: Encrypt response with user's public key
            event_logger.log_event(
                event_type=EventType.RESPONSE_ENCRYPTED,
                source_component="opa_agent",
                action="Encrypting response with user's public key",
                trace_id=trace_id,
                details={"request_id": request_id, "encryption": "RSA-OAEP-SHA256"},
                severity=Severity.INFO,
            )

            user_public_key = data["user_public_key"]
            encrypted_response = agent.encrypt_response(response_data, user_public_key)

            # Log encryption complete
            event_logger.log_event(
                event_type=EventType.RESPONSE_ENCRYPTED,
                source_component="opa_agent",
                action="Successfully encrypted response",
                trace_id=trace_id,
                details={
                    "request_id": request_id,
                    "status": "success",
                    "response_length": len(encrypted_response),
                },
                severity=Severity.INFO,
            )

            logger.info(f"[{request_id}] OPA Agent processing complete")

            # Log request completion
            event_logger.log_event(
                event_type=EventType.REQUEST_FORWARDED,
                source_component="opa_agent",
                action="Returning encrypted response to gateway",
                trace_id=trace_id,
                details={
                    "request_id": request_id,
                    "total_steps": "decrypt→opa→api→encrypt",
                },
                severity=Severity.INFO,
            )

            return (
                jsonify(
                    {
                        "encrypted_response": encrypted_response,
                        "request_id": request_id,
                        "agent_timestamp": g.request_id,
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"OPA Agent error: {e}")
            import traceback

            traceback.print_exc()

            # Log error event
            event_logger.log_event(
                event_type=EventType.ERROR,
                source_component="opa_agent",
                action="Error processing request",
                trace_id=trace_id if trace_id else "unknown",
                details={"error": str(e), "endpoint": "/evaluate"},
                status="failure",
                severity=Severity.HIGH,
            )

            return jsonify({"error": "Processing failed", "message": str(e)}), 500

    @app.route("/public-key", methods=["GET"])
    def get_public_key():
        """Get OPA Agent's public key - middleware handles auth"""
        # Log public key request
        trace_id = f"pubkey_{int(uuid.uuid4().int % 1000000)}"
        event_logger.log_event(
            event_type=EventType.REQUEST_RECEIVED,
            source_component="opa_agent",
            action="Public key requested",
            trace_id=trace_id,
            details={"endpoint": "/public-key"},
            severity=Severity.INFO,
        )

        public_key = agent.get_public_key()
        return (
            jsonify(
                {
                    "public_key": public_key,
                    "algorithm": "RSA",
                    "key_size": 2048,
                    "format": "PEM",
                }
            ),
            200,
        )

    return app  # Return 'app'


if __name__ == "__main__":
    print("=" * 60)
    print(" OPA AGENT SERVER WITH ENCRYPTION")
    print("=" * 60)
    print(f" Port: 8282")
    print(f" URL: https://localhost:8282")
    print(f" Health: https://localhost:8282/health")
    print(f" Public Key: https://localhost:8282/public-key")
    print(f" Evaluate: POST https://localhost:8282/evaluate")
    print("=" * 60)
    print("Press Ctrl+C to stop")

    # Create the Flask app
    app = create_opa_agent_app()

    # Use OPA Agent specific SSL context
    try:
        from app.ssl_config import create_opa_agent_ssl_context

        ssl_context = create_opa_agent_ssl_context()
        print("✅ Using OPA Agent dedicated SSL certificate")

        # CRITICAL: For server-side, check_hostname must be False
        ssl_context.check_hostname = False

    except ImportError:
        print("⚠️ OPA Agent SSL function not found, using server SSL")
        from app.ssl_config import create_server_ssl_context

        ssl_context = create_server_ssl_context(verify_client=False, require_mtls=False)
        ssl_context.check_hostname = False
    except Exception as e:
        print(f"⚠️ SSL error: {e}, falling back to default")
        import ssl

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.maximum_version = ssl.TLSVersion.TLSv1_2
        ssl_context.load_cert_chain(
            "certs/opa_agent/opa_agent.crt", "certs/opa_agent/opa_agent.key"
        )
        ssl_context.load_verify_locations("certs/ca.crt")
        ssl_context.verify_mode = ssl.CERT_NONE
        ssl_context.check_hostname = False

    app.run(
        host="127.0.0.1",
        port=8282,
        ssl_context=ssl_context,
        debug=True,
        extra_files=["app/opa_agent/agent.py", "app/ssl_config.py"],
    )
