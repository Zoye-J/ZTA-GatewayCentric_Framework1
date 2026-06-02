"""
Centralized SSL configuration for all services - FIXED FOR PYTHON 3.13
"""

import ssl
import os
from pathlib import Path

# Base paths
BASE_DIR = Path(__file__).parent.parent
CERTS_DIR = BASE_DIR / "certs"

# Certificate paths
CA_CERT = CERTS_DIR / "ca.crt"
SERVER_CERT = CERTS_DIR / "server.crt"
SERVER_KEY = CERTS_DIR / "server.key"


# Check if certificates exist
def verify_certificates():
    """Verify all required certificates exist"""
    missing = []

    if not CA_CERT.exists():
        missing.append(str(CA_CERT))
    if not SERVER_CERT.exists():
        missing.append(str(SERVER_CERT))
    if not SERVER_KEY.exists():
        missing.append(str(SERVER_KEY))

    if missing:
        raise FileNotFoundError(
            f"Missing SSL certificates: {', '.join(missing)}\n"
            f"Run 'python create_certificates.py' to generate certificates"
        )

    print(f"✅ SSL certificates verified")
    return True


def create_server_ssl_context(
    verify_client=False, require_mtls=False, server_side=True
):
    """
    Create standardized SSL context for SERVER applications

    Args:
        verify_client: Whether to verify client certificates
        require_mtls: Whether to require client certificates (mTLS)
        server_side: If True, disables check_hostname (only for client-side)
    """
    # Verify certificates exist first
    verify_certificates()

    # WORKAROUND FOR PYTHON 3.13 SSL BUG
    context = ssl.SSLContext(ssl.PROTOCOL_TLS)

    # CRITICAL: Force TLSv1.2 to avoid Python 3.13 bug
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    # Load server certificate chain
    context.load_cert_chain(certfile=str(SERVER_CERT), keyfile=str(SERVER_KEY))

    # Load CA certificate for client verification
    context.load_verify_locations(cafile=str(CA_CERT))

    # Configure client certificate verification
    if require_mtls:
        context.verify_mode = ssl.CERT_REQUIRED
    elif verify_client:
        context.verify_mode = ssl.CERT_OPTIONAL
    else:
        context.verify_mode = ssl.CERT_NONE

    # CRITICAL: check_hostname must be False for server-side sockets
    # This is only for client-side connections
    context.check_hostname = False  # ← FIXED: Always False for servers

    # Modern, secure cipher suites
    context.set_ciphers(
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "DHE-RSA-AES256-GCM-SHA384:"
        "DHE-RSA-AES128-GCM-SHA256"
    )

    # Additional security settings
    context.options |= ssl.OP_NO_TICKET
    context.options |= ssl.OP_SINGLE_DH_USE
    context.options |= ssl.OP_SINGLE_ECDH_USE

    return context


def create_client_ssl_context(verify_server=True, client_cert_path=None):
    """
    Create SSL context for CLIENT applications
    For clients, check_hostname should be True (or False if testing)
    """
    if not CA_CERT.exists():
        raise FileNotFoundError(f"CA certificate not found: {CA_CERT}")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    context.load_verify_locations(cafile=str(CA_CERT))

    if verify_server:
        context.verify_mode = ssl.CERT_REQUIRED
        # For client-side, we CAN enable hostname verification
        # But for localhost with self-signed certs, we'll keep it False for now
        context.check_hostname = False  # Keep False for local development
    else:
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False

    if client_cert_path and os.path.exists(client_cert_path):
        client_key = client_cert_path.with_suffix(".key")
        if client_key.exists():
            context.load_cert_chain(
                certfile=str(client_cert_path), keyfile=str(client_key)
            )

    return context


def get_ssl_context_for_service(service_name):
    """
    Get pre-configured SSL context for specific service

    Args:
        service_name: 'gateway', 'api', 'opa_agent', 'opa_server', 'dashboard'

    Returns:
        Appropriate SSL context
    """
    service_configs = {
        "gateway": {"verify_client": True, "require_mtls": False},
        "api": {"verify_client": False, "require_mtls": False},
        "opa_agent": {"verify_client": False, "require_mtls": False},
        "opa_server": {"verify_client": False, "require_mtls": False},
        "dashboard": {"verify_client": False, "require_mtls": False},
    }

    if service_name in service_configs:
        config = service_configs[service_name]
        return create_server_ssl_context(**config)
    else:
        raise ValueError(f"Unknown service: {service_name}")


def create_opa_agent_ssl_context():
    """
    Create SSL context for OPA Agent with dedicated certificate
    """
    verify_certificates()

    # Use OPA Agent specific certificate if exists
    opa_agent_cert = CERTS_DIR / "opa_agent" / "opa_agent.crt"
    opa_agent_key = CERTS_DIR / "opa_agent" / "opa_agent.key"

    if opa_agent_cert.exists() and opa_agent_key.exists():
        cert_file = str(opa_agent_cert)
        key_file = str(opa_agent_key)
        print("✅ Using OPA Agent dedicated certificate")
    else:
        cert_file = str(SERVER_CERT)
        key_file = str(SERVER_KEY)
        print("⚠️ Using shared server certificate for OPA Agent")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2

    context.load_cert_chain(certfile=cert_file, keyfile=key_file)
    context.load_verify_locations(cafile=str(CA_CERT))

    # OPA Agent doesn't require client certificates
    context.verify_mode = ssl.CERT_NONE
    context.check_hostname = False

    return context


# Helper for requests library
def get_requests_ssl_context():
    """
    Get SSL configuration for requests library

    Returns:
        Tuple of (cert, verify) for requests
    """
    verify_certificates()

    # For development with self-signed certs
    return {
        "verify": str(CA_CERT) if CA_CERT.exists() else False,
        "cert": None,  # Add client cert here if needed
    }


# Verify on import
try:
    verify_certificates()
    print("✅ Centralized SSL configuration loaded successfully")
except FileNotFoundError as e:
    print(f"⚠️ SSL configuration warning: {e}")
