# app/opa_agent/client.py - CLEANED VERSION
"""
OPA Agent Client for Gateway Server - SSL FIXED with NO FALLBACKS
=======

"""

import requests
import json
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from flask import current_app
import logging
import sys
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# Apply SSL fix - get the fixed session
from app.ssl_fix import get_ssl_fixed_session


# Apply SSL fix BEFORE any imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from app.ssl_fix import create_fixed_ssl_context

    # The patch_requests_for_python_313() is already called when ssl_fix is imported
except ImportError:
    print("⚠️ SSL fix module not available, using fallback")


logger = logging.getLogger(__name__)


class OpaAgentClient:
    def __init__(self, app=None):
        self.agent_url = None
        self.agent_public_key = None
        self.session = None

        if app:
            self.init_app(app)

    def init_app(self, app):
        """Initialize with Flask app - SSL FIXED"""
        self.agent_url = app.config.get("OPA_AGENT_URL", "https://localhost:8282")

        # Get SSL-fixed session (this handles all the Python 3.13 SSL fixes)
        self.session = get_ssl_fixed_session()
        logger.info(f"✅ Using SSL-fixed session for OPA Agent communications")

        # Load OPA Agent public key (ONCE)

        from app.mTLS.cert_manager import cert_manager

        self.agent_public_key = cert_manager.load_opa_agent_public_key()

        if self.agent_public_key:
            logger.info(
                f"✅ OPA Agent public key loaded ({len(self.agent_public_key)} chars)"
            )
        else:
            logger.error(f"❌ Failed to load OPA Agent public key")

        logger.info(
            f"✅ OPA Agent Client initialized: {self.agent_url} (SSL: FIXED CONTEXT)"
        )

    def encrypt_for_agent(self, data):
        """Encrypt data with OPA Agent's public key - WITH HYBRID ENCRYPTION for large data"""
        try:
            logger.debug(f"🔐 Encrypting data for OPA Agent")

            if not self.agent_public_key:
                logger.error("❌ OPA Agent public key not available")
                raise ValueError("OPA Agent public key not available")

            # Convert data to minimal JSON string
            data_str = json.dumps(data, separators=(",", ":"))
            data_bytes = data_str.encode("utf-8")

            # Load public key
            public_key = serialization.load_pem_public_key(
                self.agent_public_key.encode()
            )

            # Check size for RSA-2048 (max ~214 bytes with OAEP)
            max_rsa_size = 190  # Conservative limit

            if len(data_bytes) <= max_rsa_size:
                # Direct RSA encryption for small data
                logger.debug(
                    f"📏 Using direct RSA encryption ({len(data_bytes)} bytes)"
                )
                encrypted = public_key.encrypt(
                    data_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                encrypted_b64 = base64.b64encode(encrypted).decode("utf-8")
                logger.debug(
                    f"✅ Direct encryption successful: {len(encrypted_b64)} chars"
                )
                return encrypted_b64
            else:
                # HYBRID ENCRYPTION for large data
                logger.debug(
                    f"📏 Data too large for RSA ({len(data_bytes)} > {max_rsa_size}), using hybrid encryption"
                )

                # Generate random AES key and IV
                aes_key = os.urandom(32)  # 256-bit
                iv = os.urandom(12)  # 96-bit for GCM recommended

                from cryptography.hazmat.primitives.ciphers import (
                    Cipher,
                    algorithms,
                    modes,
                )
                from cryptography.hazmat.backends import default_backend

                # Encrypt data with AES-GCM
                encryptor = Cipher(
                    algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend()
                ).encryptor()

                encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()
                tag = encryptor.tag

                # Encrypt AES key with RSA
                encrypted_key = public_key.encrypt(
                    aes_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )

                # Package everything
                result = {
                    "type": "hybrid",
                    "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
                    "encrypted_data": base64.b64encode(encrypted_data).decode("utf-8"),
                    "iv": base64.b64encode(iv).decode("utf-8"),
                    "tag": base64.b64encode(tag).decode("utf-8"),
                    "algorithm": "RSA-OAEP-SHA256 + AES-256-GCM",
                }

                result_json = json.dumps(result)
                logger.debug(
                    f"✅ Hybrid encryption successful: {len(result_json)} chars"
                )
                return result_json

        except Exception as e:
            logger.error(f"❌ Encryption failed: {e}")
            raise

    def send_to_agent(self, encrypted_data, user_public_key, request_id=None):
        """Send encrypted request to OPA Agent - NO FALLBACKS, PURE SSL"""

        payload = {
            "encrypted_request": encrypted_data,
            "user_public_key": user_public_key,
            "request_id": request_id or "no-id",
        }

        try:

            logger.info(f"[{request_id}] 📡 Sending to OPA Agent")

            # Use SSL-fixed session - NO FALLBACKS
            response = self.session.post(
                f"{self.agent_url}/evaluate",
                json=payload,
                timeout=(3, 25),
                # No verify parameter - SSL context handles it
            )

            if response.status_code == 200:
                logger.info(f"[{request_id}] ✅ Received response from OPA Agent")
                return response.json()
            else:
                logger.error(
                    f"[{request_id}] ❌ OPA Agent error: {response.status_code}"
                )
                return {
                    "access_denied": True,
                    "reason": f"OPA Agent error: {response.status_code}",
                }

        except requests.exceptions.SSLError as ssl_error:
            logger.error(f"[{request_id}] ❌ SSL Error: {ssl_error}")
            # ZERO TRUST: DENY ACCESS - NO FALLBACK
            return {
                "access_denied": True,
                "reason": "SSL verification failed - secure connection required",
            }

        except requests.exceptions.ConnectionError as conn_error:
            logger.error(f"[{request_id}] ❌ Connection Error: {conn_error}")
            return {
                "access_denied": True,
                "reason": "OPA Agent unavailable - connection refused",
            }

        except Exception as e:
            logger.error(f"[{request_id}] ❌ Unexpected error: {e}")
            return {"access_denied": True, "reason": f"Internal error: {str(e)}"}

    def get_public_key(self):
        """Get OPA Agent's public key"""
        return self.agent_public_key

    def health_check(self):
        """Check if OPA Agent is healthy - NO FALLBACKS"""
        try:
            if not self.agent_public_key:
                logger.warning("⚠️ OPA Agent: No public key loaded yet")
                return False

            response = self.session.get(
                f"{self.agent_url}/health",
                timeout=5,
                # No verify parameter - SSL context handles it
            )

            return response.status_code == 200

        except Exception as e:
            logger.error(f"❌ OPA Agent health check failed: {e}")
            return False  # DENY - no fallback


# Singleton instance
_opa_agent_client = None


def init_opa_agent_client(app):
    """Initialize OPA Agent client"""

    global _opa_agent_client
    _opa_agent_client = OpaAgentClient(app)
    return _opa_agent_client


def get_opa_agent_client():
    """Get OPA Agent client instance"""

    return _opa_agent_client
