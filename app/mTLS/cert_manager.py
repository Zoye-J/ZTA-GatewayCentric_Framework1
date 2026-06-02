"""
Certificate Manager for mTLS - Complete Implementation
Handles certificate generation, validation, and management
BANGLADESH GOVERNMENT VERSION
"""

import os
import subprocess
import json
import logging
import hashlib
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from app.logs.zta_event_logger import event_logger, EventType, Severity
from flask import current_app
import requests
import base64
from app.logs.zta_event_logger import event_logger, EventType


class CertificateManager:
    def __init__(self, cert_dir="./certs"):
        self.cert_dir = cert_dir
        self.ca_cert_path = os.path.join(cert_dir, "ca.crt")
        self.ca_key_path = os.path.join(cert_dir, "ca.key")
        self.keys_dir = os.path.join(cert_dir, "user_keys")
        self.logger = logging.getLogger(__name__)

        # Bangladesh Government Structure
        self.bangladesh_departments = {
            "mod": "Ministry of Defence",
            "mof": "Ministry of Finance",
            "nsa": "National Security Agency",
        }
        self.ensure_dirs()

    def ensure_dirs(self):
        """Ensure all directories exist"""
        if not os.path.exists(self.cert_dir):
            os.makedirs(self.cert_dir)
            print(f"Created certificate directory: {self.cert_dir}")
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
            print(f"Created keys directory: {self.keys_dir}")

    def run_openssl_command(self, cmd):
        """Execute OpenSSL command with better error handling"""
        try:
            cmd = " ".join(cmd.split())
            print(f"  Running: {cmd[:80]}...")

            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                print(f"  ❌ OpenSSL Error (code {result.returncode}):")
                if result.stderr:
                    print(f"     Error: {result.stderr[:200]}")
                return False
            return True
        except subprocess.TimeoutExpired:
            print(f"  ❌ OpenSSL command timed out")
            return False
        except Exception as e:
            print(f"  ❌ Command execution error: {e}")
            return False

    def generate_root_ca(self):
        """Generate Root Certificate Authority for BANGLADESH"""
        print("🇧🇩 Generating Bangladesh Government Root CA...")

        # Generate CA private key
        ca_key_cmd = f"openssl genrsa -out {self.ca_key_path} 4096"
        if not self.run_openssl_command(ca_key_cmd):
            return False

        # Generate CA certificate with BANGLADESH context
        ca_cert_cmd = f"""
        openssl req -x509 -new -nodes -key {self.ca_key_path} \
        -sha256 -days 3650 -out {self.ca_cert_path} \
        -subj "/C=BD/ST=Dhaka Division/L=Dhaka/O=Government of Bangladesh/OU=ZTA Project/CN=Government ZTA Root CA"
        """
        if not self.run_openssl_command(ca_cert_cmd):
            return False

        print(f"✓ Bangladesh Root CA created: {self.ca_cert_path}")
        return True

    def generate_server_certificate(self, server_name="localhost"):
        """Generate server certificate for BANGLADESH government server"""
        server_key = os.path.join(self.cert_dir, "server.key")
        server_csr = os.path.join(self.cert_dir, "server.csr")
        server_crt = os.path.join(self.cert_dir, "server.crt")
        server_ext = os.path.join(self.cert_dir, "server.ext")

        print(f"🇧🇩 Generating server certificate for Bangladesh government...")

        # Generate server key
        if not self.run_openssl_command(f"openssl genrsa -out {server_key} 2048"):
            return False

        # Create CSR with BANGLADESH context
        csr_cmd = f"""
        openssl req -new -key {server_key} \
        -out {server_csr} \
        -subj "/C=BD/ST=Dhaka Division/L=Dhaka/O=Government ICT/OU=Digital Services/CN={server_name}"
        """
        if not self.run_openssl_command(csr_cmd):
            return False

        # Create extensions file
        ext_content = f"""authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = {server_name}
DNS.2 = localhost
IP.1 = 127.0.0.1
"""

        with open(server_ext, "w") as f:
            f.write(ext_content)

        # Sign certificate
        sign_cmd = f"""
        openssl x509 -req -in {server_csr} \
        -CA {self.ca_cert_path} -CAkey {self.ca_key_path} \
        -CAcreateserial -out {server_crt} \
        -days 365 -sha256 -extfile {server_ext}
        """
        if not self.run_openssl_command(sign_cmd):
            return False

        print(f"✓ Server certificate created: {server_crt}")
        return {"key": server_key, "cert": server_crt, "ca": self.ca_cert_path}

    def generate_client_certificate(self, user_id, email, department_code):
        """Generate client certificate for BANGLADESH government user"""
        # Define ALL file paths first
        client_dir = os.path.join(self.cert_dir, "clients", str(user_id))
        os.makedirs(client_dir, exist_ok=True)

        client_key = os.path.join(client_dir, "client.key")
        client_csr = os.path.join(client_dir, "client.csr")
        client_crt = os.path.join(client_dir, "client.crt")
        client_ext = os.path.join(client_dir, "client.ext")
        client_p12 = os.path.join(client_dir, "client.p12")
        metadata_file = os.path.join(client_dir, "metadata.json")

        # Get Bangladesh department name
        department_name = self.bangladesh_departments.get(
            department_code.lower(), f"Government {department_code}"
        )

        print(
            f"🇧🇩 Generating Bangladesh government certificate for {email} ({department_name})..."
        )

        # Generate client key
        if not self.run_openssl_command(f"openssl genrsa -out {client_key} 2048"):
            return None

        # Create CSR with BANGLADESH context
        csr_cmd = f"""
        openssl req -new -key {client_key} \
        -out {client_csr} \
        -subj "/C=BD/ST=Dhaka Division/L=Dhaka/O={department_name}/OU=ZTA Access/CN={email}/emailAddress={email}"
        """
        if not self.run_openssl_command(csr_cmd):
            return None

        # Create extensions file
        ext_content = f"""[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[ dn ]
C = BD
ST = Dhaka Division
L = Dhaka
O = {department_name}
OU = ZTA Access
CN = {email}
emailAddress = {email}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = email:{email}
"""

        with open(client_ext, "w") as f:
            f.write(ext_content)

        # Sign certificate
        sign_cmd = f"""
        openssl x509 -req -in {client_csr} \
        -CA {self.ca_cert_path} -CAkey {self.ca_key_path} \
        -CAcreateserial -out {client_crt} \
        -days 365 -sha256 -extfile {client_ext} -extensions v3_req
        """
        if not self.run_openssl_command(sign_cmd):
            return None

        # Create PKCS12 bundle (for browsers)
        p12_cmd = f"""
        openssl pkcs12 -export -out {client_p12} \
        -inkey {client_key} -in {client_crt} \
        -certfile {self.ca_cert_path} -passout pass:password123
        """
        self.run_openssl_command(p12_cmd)  # Optional, don't fail if this doesn't work

        # Read certificate to get fingerprint
        with open(client_crt, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            serial = format(cert.serial_number, "X")

        # Create metadata
        metadata = {
            "user_id": user_id,
            "email": email,
            "department_code": department_code,
            "department_name": department_name,
            "country": "Bangladesh",
            "region": "Dhaka Division",
            "city": "Dhaka",
            "issued_date": datetime.now().isoformat(),
            "expiry_date": (datetime.now() + timedelta(days=365)).isoformat(),
            "fingerprint": fingerprint,
            "serial_number": serial,
            "paths": {
                "key": client_key,
                "cert": client_crt,
                "p12": client_p12,
                "ca": self.ca_cert_path,
            },
        }

        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"✓ Client certificate created for {email}")
        print(f"  Certificate directory: {client_dir}")
        print(f"  Fingerprint: {fingerprint}")

        return metadata

    def validate_certificate(self, cert_pem):
        """Validate a client certificate"""
        try:
            # Parse certificate
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

            # Check if CA exists
            if not os.path.exists(self.ca_cert_path):
                return False, "CA certificate not found"

            # Load CA certificate
            with open(self.ca_cert_path, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

            # Basic validation
            now = datetime.utcnow()

            if now < cert.not_valid_before:
                return False, "Certificate not yet valid"

            if now > cert.not_valid_after:
                return False, "Certificate expired"

            # Check issuer
            if cert.issuer != ca_cert.subject:
                return False, "Certificate not issued by trusted CA"

            # Extract info
            fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            serial = format(cert.serial_number, "X")

            # Extract subject info
            subject = {}
            for attr in cert.subject:
                subject[attr.oid._name] = attr.value

            issuer = {}
            for attr in cert.issuer:
                issuer[attr.oid._name] = attr.value

            cert_info = {
                "fingerprint": fingerprint,
                "serial_number": serial,
                "subject": subject,
                "issuer": issuer,
                "not_valid_before": cert.not_valid_before.isoformat(),
                "not_valid_after": cert.not_valid_after.isoformat(),
                "raw_certificate": base64.b64encode(cert_pem.encode()).decode(),
            }

            return True, cert_info

        except Exception as e:
            return False, f"Certificate validation error: {str(e)}"

        except Exception as e:
            return False, f"Certificate validation error: {str(e)}"

    def validate_certificate_with_crl(self, cert_pem, enforce_crl=True):
        """
        Validate certificate with mandatory CRL checking
        """
        # First, basic validation
        is_valid, cert_info = self.validate_certificate(cert_pem)

        if not is_valid:
            return False, cert_info

        # Now check CRL (REQUIRED)
        if enforce_crl:
            serial = cert_info.get("serial_number")
            if self.is_certificate_revoked(serial):
                # Log revocation check
                event_logger.log_event(
                    event_type=EventType.CERTIFICATE_REVOKED,
                    source_component="cert_manager",
                    action="Revoked certificate detected",
                    details={
                        "serial": serial,
                        "fingerprint": cert_info.get("fingerprint", "")[:16],
                    },
                    severity=Severity.HIGH,
                )
                return False, "Certificate has been revoked"

        return True, cert_info

    # Also add automatic CRL refresh
    def refresh_crl(self):
        """Automatically refresh CRL from configured endpoint"""
        crl_url = os.environ.get("CRL_URL", "")
        if crl_url:
            try:
                response = requests.get(crl_url, timeout=10)
                if response.status_code == 200:
                    crl_data = response.json()
                    crl_file = os.path.join(self.cert_dir, "crl.json")
                    with open(crl_file, "w") as f:
                        json.dump(crl_data, f)
                    self.logger.info("CRL refreshed successfully")
            except Exception as e:
                self.logger.error(f"Failed to refresh CRL: {e}")

    def revoke_certificate(self, cert_pem):
        """Revoke a certificate (add to CRL)"""
        # Placeholder - in production, implement proper CRL
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            serial = format(cert.serial_number, "X")

            # Add to revocation list
            crl_file = os.path.join(self.cert_dir, "crl.json")
            if os.path.exists(crl_file):
                with open(crl_file, "r") as f:
                    revoked = json.load(f)
            else:
                revoked = []

            revoked.append(
                {
                    "serial": serial,
                    "revoked_at": datetime.now().isoformat(),
                    "reason": "user_request",
                }
            )

            with open(crl_file, "w") as f:
                json.dump(revoked, f, indent=2)

            return True, f"Certificate {serial} revoked"
        except Exception as e:
            return False, str(e)

    def is_certificate_revoked(self, serial):
        """Check if certificate is revoked"""
        crl_file = os.path.join(self.cert_dir, "crl.json")
        if os.path.exists(crl_file):
            with open(crl_file, "r") as f:
                revoked = json.load(f)
                return any(entry["serial"] == serial for entry in revoked)
        return False

    # =========================================================================
    # NEW RSA KEY FUNCTIONS - MINIMAL ADDITION
    # =========================================================================

    def generate_rsa_key_pair(self, user_id, email):
        """Generate RSA key pair for a user (simplified version)"""
        # Create user-specific directory
        user_key_dir = os.path.join(self.keys_dir, str(user_id))
        os.makedirs(user_key_dir, exist_ok=True)

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Generate public key
        public_key = private_key.public_key()

        # Serialize private key (PEM format)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Serialize public key (PEM format)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Save keys to files
        private_key_path = os.path.join(user_key_dir, "private.pem")
        public_key_path = os.path.join(user_key_dir, "public.pem")

        with open(private_key_path, "wb") as f:
            f.write(private_pem)

        with open(public_key_path, "wb") as f:
            f.write(public_pem)

        # Return key info
        return {
            "user_id": user_id,
            "email": email,
            "public_key": public_pem.decode("utf-8"),
            "private_key_path": private_key_path,
            "public_key_path": public_key_path,
            "key_size": 2048,
            "algorithm": "RSA",
            "generated_at": datetime.now().isoformat(),
        }

    def get_user_public_key(self, user_id):
        """Get user's public key from database"""
        try:
            from app.models.user import User
            from app.models import db

            user = db.session.query(User).get(user_id)
            if user and user.keys:
                return user.keys.get_public_key_pem()

            # If no keys exist, generate them
            if user:
                return user.generate_keys()

            return None
        except Exception as e:
            self.logger.error(
                f"Failed to get user public key: {e}"
            )  # ← Use self.logger
            return None

    def generate_opa_agent_keys(self):
        """Generate RSA keys for OPA Agent (simplified)"""
        try:
            print("🔑 DEBUG: Starting OPA Agent key generation...")
            agent_key_dir = os.path.join(self.cert_dir, "opa_agent")
            os.makedirs(agent_key_dir, exist_ok=True)
            print(f"🔑 DEBUG: Directory: {agent_key_dir}")

            # Generate private key
            print("🔑 DEBUG: Generating RSA private key...")
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

            # Generate public key
            print("🔑 DEBUG: Generating RSA public key...")
            public_key = private_key.public_key()

            # Serialize keys
            print("🔑 DEBUG: Serializing keys...")
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )

            # Save to files
            private_key_path = os.path.join(agent_key_dir, "private.pem")
            public_key_path = os.path.join(agent_key_dir, "public.pem")

            with open(private_key_path, "wb") as f:
                f.write(private_pem)

            with open(public_key_path, "wb") as f:
                f.write(public_pem)

            print(f"✅ OPA Agent keys generated in: {agent_key_dir}")
            print(f"✅ Public key length: {len(public_pem)} bytes")
            print(f"✅ Public key preview: {public_pem[:100].decode()}...")

            return public_pem.decode("utf-8")

        except Exception as e:
            print(f"❌ ERROR in generate_opa_agent_keys: {e}")
            import traceback

            traceback.print_exc()
            return None  # ← This returns None!

    def load_opa_agent_public_key(self):
        """Load OPA Agent's public key - GENERATE IF NOT EXISTS"""
        public_key_path = os.path.join(self.cert_dir, "opa_agent", "public.pem")

        if os.path.exists(public_key_path):
            try:
                with open(public_key_path, "r") as f:
                    key = f.read()
                if key and key.startswith("-----BEGIN PUBLIC KEY-----"):
                    print(f"✅ Loaded existing OPA Agent public key ({len(key)} chars)")
                    return key
                else:
                    print("⚠️ Existing key is invalid, regenerating...")
            except Exception as e:
                print(f"⚠️ Error loading existing key: {e}")

        # Generate new keys
        print("⚠️ OPA Agent keys not found - generating now...")
        try:
            key = self.generate_opa_agent_keys()
            if key and key.startswith("-----BEGIN PUBLIC KEY-----"):
                print(f"✅ Generated new OPA Agent public key ({len(key)} chars)")
                return key
            else:
                print("❌ Failed to generate valid key")
                return None
        except Exception as e:
            print(f"❌ Failed to generate OPA Agent keys: {e}")
            return None

    def create_p12_bundle(self, user_id, p12_password):
        """Create PKCS12 bundle for browser import"""
        try:
            client_dir = os.path.join(self.cert_dir, "clients", str(user_id))
            client_key = os.path.join(client_dir, "client.key")
            client_crt = os.path.join(client_dir, "client.crt")
            client_p12 = os.path.join(client_dir, "client.p12")

            # Check if files exist
            if not os.path.exists(client_key):
                return False, f"Private key not found: {client_key}"
            if not os.path.exists(client_crt):
                return False, f"Certificate not found: {client_crt}"
            if not os.path.exists(self.ca_cert_path):
                return False, f"CA certificate not found: {self.ca_cert_path}"

            print(f"  Creating P12 bundle for user {user_id}...")

            # Create PKCS12 bundle (for browsers)
            p12_cmd = f"""
            openssl pkcs12 -export -out "{client_p12}" \
            -inkey "{client_key}" -in "{client_crt}" \
            -certfile "{self.ca_cert_path}" -passout pass:{p12_password}
            """

            success = self.run_openssl_command(p12_cmd)
            if success:
                print(f"  ✅ P12 bundle created: {client_p12}")
                return True, client_p12
            else:
                return False, "Failed to create P12 bundle"

        except Exception as e:
            return False, str(e)


# Singleton instance
cert_manager = CertificateManager()
