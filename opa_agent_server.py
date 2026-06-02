"""
OPA Agent Server with Encryption - FIXED VERSION
Runs on Port 8282
Uses centralized SSL config
"""

from flask import Flask, request, jsonify, g
from app.opa_agent.agent import OpaAgent
import uuid
import os
import logging
import ssl
from app.logs.zta_event_logger import event_logger, EventType, Severity
import json

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
    flask_app = Flask(__name__)  # Changed variable name from app to flask_app
    agent = OpaAgent()

    @flask_app.before_request
    def setup_request():
        """Setup request context"""
        g.request_id = str(uuid.uuid4())
        g.agent = agent

    @flask_app.route("/health", methods=["GET"])
    def health():
        """Health check endpoint"""
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

    @flask_app.route("/evaluate", methods=["POST"])
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
        try:
            data = request.json
            request_id = data.get("request_id", g.request_id)

            # ADD: Get trace ID from headers or generate
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

            # ============ ADD EVENT LOGGING HERE ============
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

            # Step 1: Decrypt request with agent's private key
            encrypted_request = data["encrypted_request"]

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
                    "path": request_info.get("path", "Unknown"),
                    "user_id": request_info.get("user_id", "Unknown"),
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
                    "allowed": opa_result.get(
                        "result", False
                    ),  # ✅ FIXED: use "result"
                    "reason": opa_result.get("reason", "No reason provided"),
                },
                severity=Severity.INFO,
            )

            # Step 4: Check if access is allowed
            if not opa_result.get("result", False):  # ✅ FIXED: use "result"
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
                    user_id=request_info.get("user_id"),
                    username=request_info.get("username"),
                    details={
                        "request_id": request_id,
                        "reason": opa_result.get("reason", "Access denied"),
                        "resource": request_info.get("path"),
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
                    user_id=request_info.get("user_id"),
                    username=request_info.get("username"),
                    details={
                        "request_id": request_id,
                        "resource": request_info.get("path"),
                    },
                    severity=Severity.INFO,
                )

                # Extract API call info from request
                event_logger.log_event(
                    event_type=EventType.API_REQUEST,
                    source_component="opa_agent",
                    action="Forwarding to API Server",
                    trace_id=trace_id,
                    user_id=request_info.get("user_id"),
                    details={
                        "request_id": request_id,
                        "api_server_url": "https://localhost:5001",
                        "method": request_info.get("method"),
                        "path": request_info.get("path"),
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
                        "response_status": "success" if api_response else "error",
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

            # Log error event
            event_logger.log_event(
                event_type=EventType.ERROR,
                source_component="opa_agent",
                action="Error processing request",
                trace_id=trace_id if "trace_id" in locals() else "unknown",
                details={"error": str(e), "endpoint": "/evaluate"},
                status="failure",
                severity=Severity.HIGH,
            )

            return jsonify({"error": "Processing failed", "message": str(e)}), 500

    @flask_app.route("/public-key", methods=["GET"])
    def get_public_key():
        """Get OPA Agent's public key"""
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

    return flask_app  # Return flask_app instead of app


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
    app = create_opa_agent_app()  # Now app is the Flask application instance

    # Use OPA Agent specific SSL context
    try:
        from app.ssl_config import create_opa_agent_ssl_context

        ssl_context = create_opa_agent_ssl_context()
        print("✅ Using OPA Agent dedicated SSL certificate")
    except ImportError:
        print("⚠️ OPA Agent SSL function not found, using server SSL")
        from app.ssl_config import create_server_ssl_context

        ssl_context = create_server_ssl_context(verify_client=False, require_mtls=False)
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

    app.run(
        host="127.0.0.1",
        port=8282,
        ssl_context=ssl_context,
        debug=True,
        extra_files=["app/opa_agent/agent.py", "app/ssl_config.py"],
    )
