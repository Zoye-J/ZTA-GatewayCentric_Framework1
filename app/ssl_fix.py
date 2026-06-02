"""
Universal SSL Fix for Python 3.13 SAN bug
Workaround for "Empty Subject Alternative Name extension" error
WITH CONNECTION POOLING OPTIMIZATION
"""

import ssl
import os
import socket
import logging
from pathlib import Path
import requests
from requests.adapters import HTTPAdapter

# Add logging
logger = logging.getLogger(__name__)

# Try to apply SSL patch if available
try:
    from app.ssl_patch import apply_ssl_patch

    apply_ssl_patch()
    logger.info("✅ Applied SSL patch")
except ImportError:
    logger.warning("⚠️ SSL patch module not available, using fallback")


def create_fixed_ssl_context(verify_hostname=False):
    """
    Create SSL context that works around Python 3.13 SAN bug
    """
    # Force TLSv1.2 to avoid Python 3.13 SAN bug
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    # Load our CA certificate
    ca_cert = Path("certs/ca.crt")
    if ca_cert.exists():
        context.load_verify_locations(cafile=str(ca_cert))
        logger.info(f"✅ SSL fix: Loaded CA cert from {ca_cert}")
    else:
        logger.warning(f"⚠️ SSL fix: CA cert not found at {ca_cert}")

    # Enable certificate verification
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = False

    return context


def create_ssl_fixed_session(verify_hostname=False):
    """Create a requests Session with SSL fix AND connection pooling"""
    session = requests.Session()

    # Create custom adapter with fixed SSL context AND pooling
    class FixedSSLAdapter(HTTPAdapter):
        def __init__(self, **kwargs):
            # Increase pool size and keep connections alive
            kwargs.setdefault("pool_connections", 10)
            kwargs.setdefault("pool_maxsize", 20)
            kwargs.setdefault("max_retries", 0)
            super().__init__(**kwargs)

        def init_poolmanager(self, *args, **kwargs):
            kwargs["ssl_context"] = create_fixed_ssl_context(verify_hostname)
            # Keep connections alive across requests
            kwargs["socket_options"] = [
                (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            ]
            return super().init_poolmanager(*args, **kwargs)

    # Mount the adapter for all HTTPS requests
    session.mount("https://", FixedSSLAdapter())

    # Set connection-level timeouts (connect, read)
    session.timeout = (3, 30)

    # Force HTTP/1.1 keep-alive
    session.headers.update(
        {"Connection": "keep-alive", "Keep-Alive": "timeout=30, max=100"}
    )

    logger.info("✅ Created SSL-fixed session with connection pooling")
    return session


# Global SSL-fixed session with pooling
_ssl_fixed_session = None


def get_ssl_fixed_session():
    """Get or create SSL-fixed session with persistent connection pools"""
    global _ssl_fixed_session
    if _ssl_fixed_session is None:
        _ssl_fixed_session = create_ssl_fixed_session(verify_hostname=False)
        logger.info(
            "✅ Created global SSL-fixed session (hostname verification disabled)"
        )

    return _ssl_fixed_session


def patch_requests_library():
    """
    Monkey-patch requests library to use SSL fix globally
    """
    try:
        # Get SSL-fixed session
        session = get_ssl_fixed_session()

        # Create patched methods
        def patched_request(method, url, **kwargs):
            kwargs.pop("verify", None)
            return session.request(method, url, **kwargs)

        # Patch the module
        requests.get = lambda url, **kwargs: patched_request("GET", url, **kwargs)
        requests.post = lambda url, **kwargs: patched_request("POST", url, **kwargs)
        requests.put = lambda url, **kwargs: patched_request("PUT", url, **kwargs)
        requests.delete = lambda url, **kwargs: patched_request("DELETE", url, **kwargs)
        requests.request = patched_request

        logger.info("Successfully patched requests library with connection pooling")
        return True

    except Exception as e:
        logger.error(f"⚠️ Failed to patch requests library: {e}")
        return False


# Add this new function alongside your existing ones


def get_internal_session():
    """Session for localhost service-to-service calls with PROPER verification"""
    global _internal_session
    if _internal_session is None:
        s = requests.Session()
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=20, max_retries=0)
        s.mount("https://", adapter)
        # Use proper SSL context instead of verify=False
        s.verify = str(Path("certs/ca.crt").absolute())  # ← Use CA cert
        s.headers.update({"Connection": "keep-alive"})
        _internal_session = s
        logger.info("✅ Created internal session with proper CA verification")
    return _internal_session


_internal_session = None

# Apply patch when module is imported
patch_requests_library()


__all__ = [
    "create_fixed_ssl_context",
    "create_ssl_fixed_session",
    "get_ssl_fixed_session",
    "patch_requests_library",
]
