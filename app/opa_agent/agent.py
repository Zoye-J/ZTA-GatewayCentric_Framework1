# app/opa_agent/agent.py

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from app.ssl_fix import get_ssl_fixed_session, patch_requests_library

    patch_requests_library()
    HAS_SSL_FIX = True
except ImportError:
    HAS_SSL_FIX = False
    print("⚠️ SSL fix not available in agent.py")

import json
import requests
from flask import current_app
import logging
from app.opa_agent.crypto_handler import CryptoHandler
from datetime import datetime

logger = logging.getLogger(__name__)


class OpaAgent:
    def __init__(self):
        self.crypto = CryptoHandler()

        # Generate/load keys FIRST
        self.agent_private_key, self.agent_public_key = self._load_or_generate_keys()

        # Verify keys exist
        if not self.agent_private_key or not self.agent_public_key:
            raise ValueError("Failed to initialize OPA Agent RSA keys")

        # Log key info
        logger.info(f"OPA Agent initialized with keys")
        logger.info(f"Private key length: {len(self.agent_private_key)}")
        logger.info(f"Public key length: {len(self.agent_public_key)}")

        self.opa_url = "https://localhost:8181"
        self.api_server_url = "https://localhost:5001"

        # Cache session at instance level — avoid re-fetching on every call
        from app.ssl_fix import get_ssl_fixed_session

        self._session = get_ssl_fixed_session()
        logger.info("✅ OPA Agent: SSL session cached at instance level")

    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones AND SAVE THEM"""
        import os
        from app.mTLS.cert_manager import cert_manager

        # Try to load from certs/opa_agent directory
        opa_agent_dir = os.path.join(cert_manager.cert_dir, "opa_agent")
        private_key_path = os.path.join(opa_agent_dir, "private.pem")
        public_key_path = os.path.join(opa_agent_dir, "public.pem")

        # Ensure directory exists
        os.makedirs(opa_agent_dir, exist_ok=True)

        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            try:
                with open(private_key_path, "r") as f:
                    private_key = f.read()
                with open(public_key_path, "r") as f:
                    public_key = f.read()

                # Validate the keys are actually valid PEM
                if "-----BEGIN" in private_key and "-----BEGIN" in public_key:
                    logger.info("Loaded existing OPA Agent keys from disk")
                    return private_key, public_key
                else:
                    logger.warning("Existing keys are invalid, regenerating...")
            except Exception as e:
                logger.warning(f"Failed to load existing keys: {e}")

        # Generate new keys
        logger.info("Generating new OPA Agent keys")
        private_key, public_key = self.crypto.generate_key_pair()

        # Convert bytes to string if needed
        if isinstance(private_key, bytes):
            private_key = private_key.decode("utf-8")
        if isinstance(public_key, bytes):
            public_key = public_key.decode("utf-8")

        # Save keys to disk
        try:
            with open(private_key_path, "w") as f:
                f.write(private_key)
            with open(public_key_path, "w") as f:
                f.write(public_key)
            logger.info(f"✅ Saved OPA Agent keys to {opa_agent_dir}/")
        except Exception as e:
            logger.error(f"Failed to save OPA Agent keys: {e}")
            # Continue anyway - keys are still in memory

        return private_key, public_key

    def decrypt_request(self, encrypted_data):
        """Decrypt incoming request from Gateway - handles hybrid encryption"""
        try:
            # Check if this is hybrid encrypted (starts with {)
            if encrypted_data.startswith("{"):
                try:
                    package = json.loads(encrypted_data)
                    if package.get("type") == "hybrid":
                        # Use crypto_handler's hybrid decryption
                        return self.crypto._hybrid_decrypt(
                            package, self.agent_private_key
                        )
                except:
                    pass  # Not JSON or not hybrid, continue with direct

            # Direct RSA decryption
            return self.crypto.decrypt_from_user(encrypted_data, self.agent_private_key)
        except Exception as e:
            logger.error(f"Failed to decrypt request: {e}")
            raise

    def evaluate_with_risk(self, request_data):
        """Evaluate request with risk scoring"""
        from app.services.risk_scorer import RiskScorer

        # Calculate risk score
        scorer = RiskScorer()
        resource_sensitivity = request_data.get("resource", {}).get(
            "classification", "PUBLIC"
        )
        risk_score = scorer.calculate_risk(request_data, resource_sensitivity)
        risk_level = scorer.get_risk_level(risk_score)

        # Add risk to request data
        request_data["risk"] = {
            "score": risk_score,
            "level": risk_level,
            "threshold": 50,  # Score above 50 requires additional checks
        }

        print(f"📊 Risk Score: {risk_score} ({risk_level})")

        # Call OPA Server with risk info
        opa_input = {
            "input": {
                **request_data,
                "risk_score": risk_score,
                "risk_level": risk_level,
            }
        }

        # Send to OPA Server
        response = requests.post(
            "https://localhost:8181/v1/data/zta/allow", json=opa_input, timeout=5
        )

        if response.status_code == 200:
            result = response.json()
            result["risk_assessment"] = {
                "score": risk_score,
                "level": risk_level,
                "factors_considered": ["time", "location", "device", "authentication"],
            }
            return result

        return {"allow": False, "reason": "OPA Server error"}

    def encrypt_response(self, data, user_public_key):
        """Encrypt response for specific user"""
        try:
            return self.crypto.encrypt_for_user(json.dumps(data), user_public_key)
        except Exception as e:
            logger.error(f"Failed to encrypt response: {e}")
            raise

    def query_opa_server(self, request_data):
        """Forward request to OPA Server for policy evaluation"""
        try:
            logger.info(f"Querying OPA Server: {self.opa_url}")

            # Prepare input for OPA
            opa_input = self._prepare_opa_input(request_data)

            session = self._session

            # The session already has proper SSL context
            response = session.post(
                f"{self.opa_url}/v1/data/zta/allow",
                json={"input": opa_input},
                timeout=(2, 8),
            )

            if response.status_code == 200:
                result = response.json()
                logger.info(f"OPA Server response: {result}")

                # Return in the format expected by opa_agent_server.py
                # The server expects "result" and "reason" fields
                if isinstance(result, dict):
                    return {
                        "result": result.get("result", False),
                        "reason": result.get("reason", "No reason provided"),
                        "decision": result.get("decision", {}),
                    }
                return {"result": False, "reason": "Invalid response format"}
            else:
                logger.error(
                    f"OPA Server error: {response.status_code} - {response.text}"
                )
                return {
                    "result": False,
                    "reason": f"OPA Server error: {response.status_code}",
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to connect to OPA Server: {e}")
            return {"result": False, "reason": f"OPA Server unavailable: {str(e)}"}

    def call_api_server(self, request_info):
        """Call API Server after OPA approval"""
        try:
            # Extract the actual API endpoint and method
            endpoint = request_info.get("endpoint")  # ← NO FALLBACK
            method = request_info.get("method", "GET").upper()
            data = request_info.get("data")
            user_claims = request_info.get("user", {})

            # CRITICAL: If no endpoint, this is an error - DENY ACCESS
            if not endpoint:
                logger.error("No endpoint provided in request_info - DENYING ACCESS")
                return {
                    "status_code": 403,
                    "error": "No endpoint specified",
                    "success": False,
                }

            logger.info(f"Calling API Server: {method} {endpoint}")

            # Prepare headers for API Server - USE THE CORRECT SERVICE TOKEN
            headers = {
                "Content-Type": "application/json",
                "X-Service-Token": "api-token-2024-zta",  # ← MUST match api_server.py
                "X-Request-ID": request_info.get("request_id", "unknown"),
                "X-User-Claims": json.dumps(user_claims),
                "X-Forwarded-By": "OPA-Agent",
            }

            # Log the headers (without sensitive data)
            logger.info(
                f"Request headers: X-Service-Token present, X-Request-ID: {headers['X-Request-ID']}"
            )

            session = self._session

            # Make the request to API Server
            url = f"{self.api_server_url}{endpoint}"
            logger.info(f"Making request to: {url}")

            if method == "POST":
                response = session.post(
                    url,
                    json=data,
                    headers=headers,
                    timeout=10,
                )
            elif method == "PUT":
                response = session.put(
                    url,
                    json=data,
                    headers=headers,
                    timeout=10,
                )
            elif method == "DELETE":
                response = session.delete(
                    url,
                    headers=headers,
                    timeout=10,
                )
            else:  # GET
                response = session.get(
                    url,
                    headers=headers,
                    timeout=10,
                )

            logger.info(f"API Server response status: {response.status_code}")

            # If we got 401, log the response body for debugging
            if response.status_code == 401:
                try:
                    error_body = response.text
                    logger.error(f"API Server 401 response: {error_body[:200]}")
                except:
                    pass

            # Prepare response
            api_response = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "success": 200 <= response.status_code < 300,
            }

            try:
                if response.headers.get("Content-Type", "").startswith(
                    "application/json"
                ):
                    api_response["data"] = response.json()
                else:
                    api_response["data"] = response.text
            except:
                api_response["data"] = response.text

            return api_response

        except requests.exceptions.Timeout:
            logger.error("API Server request timeout")
            return {"status_code": 504, "error": "API Server timeout", "success": False}
        except requests.exceptions.RequestException as e:
            logger.error(f"API Server connection failed: {e}")
            return {
                "status_code": 503,
                "error": f"API Server unavailable: {str(e)}",
                "success": False,
            }
        except Exception as e:
            logger.error(f"Unexpected error calling API Server: {e}")
            return {
                "status_code": 500,
                "error": f"Internal error: {str(e)}",
                "success": False,
            }

    def _prepare_opa_input(self, request_data):
        """Prepare input data for OPA Server - HANDLES MINIMAL DATA"""

        # Handle both full and minimal data formats
        if "u" in request_data:  # Minimal format
            user_data = request_data.get("u", {})
            resource_data = request_data.get("r", {})
            env_data = request_data.get("e", {})

            # Map the field names correctly for OPA
            # OPA expects: input.user.clearance, input.resource.classification
            user = {
                "id": 0,
                "username": "user",
                "role": "user",
                "department": user_data.get("d", ""),
                "facility": "",
                "clearance": user_data.get("c", "BASIC"),  # This maps correctly
                "email": "",
            }
            resource = {
                "type": "document",
                "id": resource_data.get("id"),
                "classification": resource_data.get(
                    "c", "BASIC"
                ),  # This maps correctly
                "department": resource_data.get("d", ""),  # Department name
                "facility": "",
                "category": "",
            }
            environment = {
                "timestamp": datetime.now().isoformat(),
                "current_hour": env_data.get("h", 12),
                "client_ip": "127.0.0.1",
            }
            request_id = request_data.get("id", "unknown")

            # IMPORTANT: Log what we're sending to OPA
            print(
                f"🔍 Sending to OPA - User dept: {user['department']}, Resource dept: {resource['department']}"
            )
            print(
                f"🔍 User clearance: {user['clearance']}, Resource class: {resource['classification']}"
            )

        else:  # Full format
            user = request_data.get("user", {})
            resource = request_data.get("resource", {})
            environment = request_data.get("environment", {})
            request_id = request_data.get("request_id", "unknown")

        return {
            "user": {
                "id": user.get("id") or 0,
                "username": user.get("username") or "user",
                "role": user.get("role") or "user",
                "department": user.get("department", ""),
                "facility": user.get("facility", ""),
                "clearance": user.get("clearance", "BASIC"),
                "email": user.get("email", ""),
            },
            "resource": {
                "type": resource.get("type", "document"),
                "id": resource.get("id"),
                "classification": resource.get("classification", "BASIC"),
                "department": resource.get("department", ""),
                "facility": resource.get("facility", ""),
                "category": resource.get("category", ""),
            },
            "environment": {
                "timestamp": environment.get("timestamp", datetime.now().isoformat()),
                "current_hour": environment.get("current_hour", datetime.now().hour),
                "client_ip": environment.get("client_ip", "127.0.0.1"),
            },
            "request_id": request_id,
        }

    def _extract_resource_type(self, endpoint):
        """Extract resource type from endpoint"""
        if "/documents" in endpoint:
            return "document"
        elif "/users" in endpoint:
            return "user"
        elif "/logs" in endpoint:
            return "log"
        elif "/auth" in endpoint:
            return "auth"
        else:
            return "unknown"

    def get_public_key(self):
        """Get OPA Agent's public key"""
        return self.agent_public_key

    def health_check(self):
        """Check health of OPA Agent dependencies"""
        health = {
            "agent": "running",
            "opa_server": "unknown",
            "api_server": "unknown",
            "encryption": "available",
        }

        # Check OPA Server
        try:
            response = requests.get(f"{self.opa_url}/health", timeout=3)
            health["opa_server"] = (
                "healthy" if response.status_code == 200 else "unhealthy"
            )
        except:
            health["opa_server"] = "unreachable"

        # Check API Server
        try:
            response = requests.get(
                f"{self.api_server_url}/health", timeout=3, verify=False
            )
            health["api_server"] = (
                "healthy" if response.status_code == 200 else "unhealthy"
            )
        except:
            health["api_server"] = "unreachable"

        return health

    def process_request(self, encrypted_request, user_public_key, request_id):
        """
        Complete request processing:
        1. Decrypt request
        2. Query OPA Server
        3. If allowed, call API Server
        4. Encrypt response
        """
        try:
            logger.info(f"[{request_id}] Starting OPA Agent processing")

            # Step 1: Decrypt request
            decrypted_data = self.decrypt_request(encrypted_request)
            request_info = json.loads(decrypted_data)
            request_info["request_id"] = request_id

            logger.info(
                f"[{request_id}] Decrypted request from user: {request_info.get('user', {}).get('username')}"
            )

            # Step 2: Query OPA Server
            opa_result = self.query_opa_server(request_info)

            # Check OPA decision
            if not opa_result.get("result", False):
                logger.info(
                    f"[{request_id}] OPA denied access: {opa_result.get('reason', 'No reason')}"
                )
                response_data = {
                    "allowed": False,
                    "reason": opa_result.get("reason", "Access denied by policy"),
                    "opa_result": opa_result,
                    "request_id": request_id,
                }
            else:
                # Step 3: Call API Server
                logger.info(f"[{request_id}] OPA allowed access, calling API Server")
                api_response = self.call_api_server(request_info)

                response_data = {
                    "allowed": True,
                    "api_response": api_response,
                    "opa_result": opa_result,
                    "request_id": request_id,
                }

            # Step 4: Encrypt response
            encrypted_response = self.encrypt_response(response_data, user_public_key)

            logger.info(f"[{request_id}] OPA Agent processing complete")

            return {
                "encrypted_response": encrypted_response,
                "request_id": request_id,
                "agent_timestamp": request_id,
            }

        except json.JSONDecodeError as e:
            logger.error(f"[{request_id}] Invalid JSON in request: {e}")
            raise ValueError(f"Invalid request data: {str(e)}")
        except Exception as e:
            logger.error(f"[{request_id}] OPA Agent processing failed: {e}")
            raise
