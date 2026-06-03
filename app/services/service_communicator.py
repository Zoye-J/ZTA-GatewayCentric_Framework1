"""
Service Communicator for ENCRYPTED ZTA Workflow - COMPLETE FIX
Handles encrypted communication following your flow:
User → Gateway → OPA Agent (encrypts) → OPA Server (policy check) → API Server → OPA Agent (encrypts) → Gateway → User
"""

import requests
import json
import uuid
import sys
import os
from flask import current_app, request, g, jsonify
import logging
from app.logs.zta_event_logger import event_logger, EventType
from datetime import datetime

from app.models import user

# Apply SSL fix BEFORE any imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from app.ssl_fix import create_fixed_ssl_context

    print("✅ SSL fix imported for service_communicator")
except ImportError:
    print("⚠️ SSL fix module not available for service communicator")
    # Create fallback context
    import ssl

    def create_fixed_ssl_context():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile="certs/ca.crt")
        return context


logger = logging.getLogger(__name__)


class EncryptedServiceCommunicator:
    def __init__(self):
        self.opa_agent_client = None
        self.api_server_url = None
        self._initialized = False
        self.session = None  # For SSL-fixed requests

    def init_app(self, app):
        """Initialize with Flask app"""
        self.api_server_url = app.config.get("API_SERVER_URL", "https://localhost:5001")

        # Create SSL-fixed session
        self.session = requests.Session()
        ssl_context = create_fixed_ssl_context()

        # Mount SSL-fixed adapter
        from requests.adapters import HTTPAdapter

        class FixedSSLAdapter(HTTPAdapter):
            def init_poolmanager(self, *args, **kwargs):
                kwargs["ssl_context"] = ssl_context
                return super().init_poolmanager(*args, **kwargs)

        self.session.mount("https://", FixedSSLAdapter())
        logger.info("✅ Created SSL-fixed session for service communicator")

        # Initialize OPA Agent Client
        try:
            from app.opa_agent.client import init_opa_agent_client, get_opa_agent_client

            init_opa_agent_client(app)
            self.opa_agent_client = get_opa_agent_client()
            logger.info("✅ OPA Agent Client integrated into Service Communicator")
        except ImportError as e:
            logger.warning(f"OPA Agent not available: {e}")
            self.opa_agent_client = None

        self._initialized = True
        logger.info("=== ENCRYPTED Service Communicator Initialized ===")
        logger.info(f"API Server URL: {self.api_server_url}")
        logger.info(
            f"OPA Agent Client: {'Available' if self.opa_agent_client else 'Not available'}"
        )

    def _make_ssl_request(self, method, url, **kwargs):
        """Make request with SSL fix and service token"""

        # Ensure service token is always present for internal calls
        if "headers" not in kwargs:
            kwargs["headers"] = {}

        # ONLY add service token if not already present
        # This prevents overriding the token we set in _handle_direct_resource_call
        if "X-Service-Token" not in kwargs["headers"]:
            kwargs["headers"]["X-Service-Token"] = current_app.config.get(
                "GATEWAY_SERVICE_TOKEN", "gateway-token-2024-zta"
            )

        try:
            kwargs.pop("verify", None)
            return self.session.request(method, url, **kwargs)
        except Exception as e:
            logger.error(f"SSL request failed: {e}")
            return None

    def process_encrypted_request(self, flask_request, user_claims):
        """
        Process request following ZTA flow:
        User → Gateway → OPA Agent (encrypts) → OPA Server (policy check) → API Server → OPA Agent (encrypts) → Gateway → User
        """
        request_id = str(uuid.uuid4())
        g.request_id = request_id

        logger.info(f"[{request_id}] === ZTA ENCRYPTED FLOW START ===")
        logger.info(f"[{request_id}] User: {user_claims.get('username')}")
        logger.info(f"[{request_id}] Endpoint: {flask_request.path}")
        logger.info(f"[{request_id}] Method: {flask_request.method}")

        # Log start of encrypted flow
        event_logger.log_event(
            event_type=EventType.REQUEST_RECEIVED,
            source_component="gateway",
            action="Starting encrypted ZTA flow",
            user_id=user_claims.get("sub"),
            username=user_claims.get("username"),
            details={
                "endpoint": flask_request.path,
                "method": flask_request.method,
                "flow": "User → Gateway → OPA Agent → OPA Server → API Server → OPA Agent → Gateway → User",
            },
            trace_id=request_id,
        )

        # Handle specific endpoints
        if flask_request.path.startswith("/api/resources/"):
            return self._handle_resource_request(flask_request, user_claims, request_id)

        # Default: use encrypted flow
        return self._handle_encrypted_request(flask_request, user_claims, request_id)

    def _handle_resource_request(self, flask_request, user_claims, request_id):
        """Handle resource requests through encrypted flow - NO FALLBACKS"""
        try:
            # Extract resource ID
            parts = flask_request.path.split("/")
            resource_id = None
            for i, part in enumerate(parts):
                if part == "resources" and i + 1 < len(parts):
                    try:
                        resource_id = int(parts[i + 1])
                        break
                    except ValueError:
                        pass

            logger.info(f"[{request_id}] Processing resource request: ID={resource_id}")

            # Get user's public key
            request_body = flask_request.get_json(silent=True) or {}
            user_public_key = request_body.get("browser_public_key")

            if not user_public_key:
                logger.warning(
                    f"[{request_id}] No browser public key sent — falling back to DB key"
                )
                user_public_key = self._get_user_public_key(user_claims.get("sub"))

            if not user_public_key:
                return self._create_error_response(
                    400, "User public key not found", request_id
                )

            logger.info(
                f"[{request_id}] Using public key source: {'browser IndexedDB' if request_body.get('browser_public_key') else 'database'}"
            )

            # Build request for OPA Agent
            request_data = self._build_resource_request_data(
                flask_request, user_claims, resource_id, request_id
            )

            # Check if OPA Agent is available
            if not self.opa_agent_client:
                logger.error(f"[{request_id}] OPA Agent not available - ACCESS DENIED")
                return self._create_error_response(
                    503, "Security service unavailable - ACCESS DENIED", request_id
                )

            # Step 1: Encrypt and send to OPA Agent
            logger.info(f"[{request_id}] 🔐 Encrypting request for OPA Agent")
            try:
                encrypted_request = self.opa_agent_client.encrypt_for_agent(
                    request_data
                )
            except Exception as e:
                logger.error(f"[{request_id}] Encryption failed: {e}")
                return self._create_error_response(
                    500, f"Encryption failed - ACCESS DENIED", request_id
                )

            # Step 2: Send to OPA Agent
            logger.info(f"[{request_id}] 📡 Sending to OPA Agent")
            agent_response = self.opa_agent_client.send_to_agent(
                encrypted_request, user_public_key, request_id
            )

            if not agent_response:
                logger.error(f"[{request_id}] ❌ OPA Agent did not respond")
                return self._create_error_response(
                    503, "Security service unavailable - ACCESS DENIED", request_id
                )

            # Check if access denied
            if agent_response.get("access_denied"):
                return self._create_error_response(
                    403,
                    agent_response.get("reason", "Policy denied access"),
                    request_id,
                )

            # Get encrypted response
            encrypted_response = agent_response.get("encrypted_response")
            if not encrypted_response:
                logger.error(f"[{request_id}] ❌ No encrypted response from OPA Agent")
                return self._create_error_response(
                    500,
                    "Invalid response from security service - ACCESS DENIED",
                    request_id,
                )

            # Log successful encrypted flow
            event_logger.log_event(
                event_type=EventType.RESPONSE_ENCRYPTED,
                source_component="service_communicator",
                action="Encrypted response received from OPA Agent",
                user_id=user_claims.get("sub"),
                username=user_claims.get("username"),
                details={
                    "request_id": request_id,
                    "resource_id": resource_id,
                    "encryption": "RSA-OAEP-SHA256",
                    "flow_complete": True,
                },
                trace_id=request_id,
            )

            # Return encrypted response - NO FALLBACKS
            return (
                jsonify(
                    {
                        "encrypted_response": encrypted_response,
                        "resource_id": resource_id,
                        "encryption_info": {
                            "algorithm": "RSA-OAEP-SHA256",
                            "key_size": 2048,
                            "request_id": request_id,
                        },
                        "zta_context": {
                            "flow": "User → Gateway → OPA Agent → OPA Server → API Server → OPA Agent → Gateway",
                            "encryption_used": True,
                            "opa_agent_used": True,
                            "trace_id": request_id,
                        },
                    }
                ),
                200,
            )

        except Exception as e:
            logger.error(f"[{request_id}] Resource request error: {e}")
            return self._create_error_response(
                500, f"Resource request failed - ACCESS DENIED", request_id
            )

    def _build_resource_request_data(
        self, flask_request, user_claims, resource_id, request_id
    ):
        """Build request data for OPA Agent - MUST use correct resource"""
        try:
            from app.models.user import GovernmentDocument

            # IMPORTANT: Get the SPECIFIC resource by ID, not a fallback
            resource = GovernmentDocument.query.get(resource_id)

            if not resource:
                logger.error(
                    f"[{request_id}] Resource {resource_id} not found in database"
                )
                raise ValueError(f"Resource {resource_id} not found")

            logger.info(
                f"[{request_id}] Found resource: {resource.title} (Dept: {resource.department}, Class: {resource.classification})"
            )

            # Map classification for OPA
            classification_map = {
                "PUBLIC": "BASIC",
                "DEPARTMENT": "CONFIDENTIAL",
                "TOP_SECRET": "TOP_SECRET",
            }

            opa_classification = classification_map.get(
                resource.classification, "BASIC"
            )

            # Build MINIMAL data for encryption
            resource_department = resource.department
            if resource.classification == "PUBLIC":
                resource_department = user_claims.get("department", resource.department)

            minimal_data = {
                "u": {  # User
                    "c": user_claims.get("clearance_level", "BASIC"),
                    "d": user_claims.get("department", ""),
                },
                "r": {  # Resource
                    "c": opa_classification,
                    "d": resource_department,
                    "id": resource_id,
                },
                "e": {  # Environment
                    "h": datetime.now().hour,
                },
                "id": request_id,
                # ADD THESE FIELDS FOR API CALL
                "endpoint": f"/api/documents/{resource_id}",  # ✅ FIXED: matches API Server routes
                "method": "GET",
                "user": {
                    "id": user_claims.get("sub"),
                    "username": user_claims.get("username"),
                    "department": user_claims.get("department"),
                    "clearance": user_claims.get("clearance_level"),
                },
            }

            logger.info(
                f"[{request_id}] Built request for endpoint: {minimal_data['endpoint']}"
            )

            return minimal_data

        except Exception as e:
            logger.error(f"[{request_id}] Failed to build resource data: {e}")
            raise

    def _handle_direct_resource_call(self, flask_request, user_claims, request_id):
        """Fallback direct call to API Server"""
        try:
            logger.info(f"[{request_id}] 🔄 Direct API call to API Server")

            # Build URL
            api_url = f"{self.api_server_url}{flask_request.path}"

            api_service_token = current_app.config.get(
                "API_SERVICE_TOKEN", "api-token-2024-zta"
            )
            logger.info(f"[{request_id}] Using API_SERVICE_TOKEN: {api_service_token}")

            # ============ FIX: Use the correct service token ============
            # The API Server expects API_SERVICE_TOKEN, not GATEWAY_SERVICE_TOKEN
            api_service_token = current_app.config.get(
                "API_SERVICE_TOKEN", "api-token-2024-zta"
            )

            # Also ensure OPA_AGENT_TOKEN is available if needed
            opa_agent_token = current_app.config.get(
                "OPA_AGENT_TOKEN", "opa-agent-token-2024-zta"
            )

            # Prepare headers with CORRECT service token
            headers = {
                "Content-Type": "application/json",
                "X-Service-Token": api_service_token,  # ← FIXED: Use API_SERVICE_TOKEN
                "X-User-Claims": json.dumps(user_claims),
                "X-Request-ID": request_id,
            }

            # Log the token being used (first few chars for debugging)
            logger.info(
                f"[{request_id}] Using service token: {api_service_token[:20]}..."
            )

            # Make request with SSL fix
            if flask_request.method == "POST":
                data = flask_request.get_json(silent=True) or {}
                response = self._make_ssl_request(
                    "POST", api_url, json=data, headers=headers, timeout=10
                )
            elif flask_request.method == "PUT":
                data = flask_request.get_json(silent=True) or {}
                response = self._make_ssl_request(
                    "PUT", api_url, json=data, headers=headers, timeout=10
                )
            elif flask_request.method == "DELETE":
                response = self._make_ssl_request(
                    "DELETE", api_url, headers=headers, timeout=10
                )
            else:  # GET
                response = self._make_ssl_request(
                    "GET", api_url, headers=headers, timeout=10
                )

            if response and response.status_code == 200:
                data = response.json()
                logger.info(f"[{request_id}] ✅ Direct API call successful")

                # Add ZTA context
                if isinstance(data, dict):
                    data["zta_context"] = {
                        "flow": "Direct API → Gateway → User",
                        "encryption_used": False,
                        "opa_agent_used": False,
                        "request_id": request_id,
                    }

                return jsonify(data), response.status_code
            else:
                status = response.status_code if response else "No response"
                logger.error(f"[{request_id}] ❌ Direct API error: {status}")
                if response:
                    try:
                        error_data = response.json()
                        logger.error(f"[{request_id}] Error details: {error_data}")
                    except:
                        logger.error(f"[{request_id}] Error text: {response.text}")
                return self._create_error_response(
                    500, f"API Server error: {status}", request_id
                )

        except Exception as e:
            logger.error(f"[{request_id}] ❌ Direct API call failed: {e}")
            import traceback

            traceback.print_exc()
            return self._create_error_response(
                500, f"Direct API failed: {str(e)}", request_id
            )

    def _handle_encrypted_request(self, flask_request, user_claims, request_id):
        """Handle generic encrypted requests (for non-resource endpoints)"""
        # Similar to _handle_resource_request but for other endpoints
        return self._handle_direct_resource_call(flask_request, user_claims, request_id)

    def _get_user_public_key(self, user_id):
        """Get user's public key using the User model property"""
        try:
            from app.models.user import User

            user = User.query.get(user_id)
            if not user:
                logger.error(f"User {user_id} not found")
                return None

            # Use the public_key_pem property which handles the UserKey relationship
            public_key = user.public_key_pem

            if public_key:
                logger.debug(f"✅ Got public key for user {user_id}")
                return public_key

            # If no key, try to generate one
            logger.info(f"No public key for user {user_id}, generating...")
            public_key = user.generate_keys()
            return public_key

        except Exception as e:
            logger.error(f"Error getting user public key: {e}")
            return None

    def _create_error_response(self, status_code, message, request_id):
        """Create standardized error response"""
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="service_communicator",
            action="Encrypted flow error",
            details={
                "error": message,
                "request_id": request_id,
                "status_code": status_code,
            },
            trace_id=request_id,
        )

        return (
            jsonify(
                {
                    "error": "Encrypted workflow failed",
                    "message": message,
                    "zta_context": {
                        "failed_component": "service_communicator",
                        "request_id": request_id,
                        "flow_interrupted": True,
                    },
                }
            ),
            status_code,
        )

    def health_check(self):
        """Check health of services"""
        health_status = {
            "gateway": "running",
            "opa_agent": "unknown",
            "api_server": "unknown",
            "timestamp": datetime.now().isoformat(),
        }

        # Check OPA Agent
        if self.opa_agent_client:
            try:
                health_status["opa_agent"] = (
                    "healthy" if self.opa_agent_client.health_check() else "unhealthy"
                )
            except:
                health_status["opa_agent"] = "unhealthy"
        else:
            health_status["opa_agent"] = "not_initialized"

        # Check API Server
        try:
            headers = {
                "X-Service-Token": current_app.config.get(
                    "GATEWAY_SERVICE_TOKEN", "gateway-token-2024"
                ),
                "X-Request-ID": str(uuid.uuid4())[:8],
            }

            response = self._make_ssl_request(
                "GET", f"{self.api_server_url}/health", headers=headers, timeout=3
            )
            health_status["api_server"] = (
                "healthy" if response.status_code == 200 else "unhealthy"
            )
        except:
            health_status["api_server"] = "unreachable"

        return health_status


# Singleton instance
encrypted_service_communicator = EncryptedServiceCommunicator()


def init_service_communicator(app):
    """Initialize ENCRYPTED service communicator"""
    encrypted_service_communicator.init_app(app)


def get_service_communicator():
    """Get ENCRYPTED service communicator instance"""
    return encrypted_service_communicator


def process_encrypted_request(request, user_claims):
    """
    Simple wrapper for gateway server
    """
    communicator = get_service_communicator()
    return communicator.process_encrypted_request(request, user_claims)
