import os
import secrets
from datetime import timedelta


class Config:
    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "government-secure-key-change-in-production-2024"
    )
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///government_zta.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ============ BANGLADESH CONTEXT CONFIGURATION ============
    BANGLADESH_TIMEZONE = "Asia/Dhaka"  # UTC+6
    BANGLADESH_WORKING_HOURS = {"start": 9, "end": 17}  # 9 AM to 5 PM Bangladesh time

    # Bangladesh Government Departments
    BANGLADESH_DEPARTMENTS = {
        "mod": {
            "name": "Ministry of Defence",
            "code": "mod",
            "email_domain": "@mod.gov",
            "clearance_levels": ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"],
            "resource_categories": [
                "Strategy",
                "Operations",
                "Budget",
                "Personnel",
                "Intelligence",
                "Weapons",
            ],
        },
        "mof": {
            "name": "Ministry of Finance",
            "code": "mof",
            "email_domain": "@mof.gov",
            "clearance_levels": ["BASIC", "CONFIDENTIAL", "SECRET"],
            "resource_categories": [
                "Budget",
                "Finance",
                "Tax",
                "Policy",
                "Procurement",
            ],
        },
        "nsa": {
            "name": "National Security Agency",
            "code": "nsa",
            "email_domain": "@nsa.gov",
            "clearance_levels": ["CONFIDENTIAL", "SECRET", "TOP_SECRET"],
            "resource_categories": [
                "Intelligence",
                "Security",
                "Technology",
                "Cyber",
                "Surveillance",
            ],
        },
    }

    # Bangladesh Holidays 2024
    BANGLADESH_HOLIDAYS = [
        "2024-02-21",  # Language Martyrs' Day
        "2024-03-26",  # Independence Day
        "2024-04-14",  # Bengali New Year
        "2024-05-01",  # May Day
        "2024-12-16",  # Victory Day
        "2024-12-25",  # Christmas Day
    ]

    # Bangladesh Certificate Authority Details
    BANGLADESH_CERT_DETAILS = {
        "country": "BD",
        "state": "Dhaka Division",
        "locality": "Dhaka",
        "organization": "Government of Bangladesh",
        "organizational_unit": "ZTA Project",
    }

    # Bangladesh Security Settings
    BANGLADESH_IP_RANGES = {
        "government": ["103.15.0.0/16", "203.112.0.0/16"],  # Govt IP ranges
        "chattogram": ["103.16.0.0/16"],
        "restricted": [],  # Add restricted IPs if needed
    }

    # JWT (Only for Gateway Server)
    _default_jwt_secret = secrets.token_urlsafe(32)
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", _default_jwt_secret)
    if not os.environ.get("JWT_SECRET_KEY"):
        import warnings

        warnings.warn(
            "⚠️ JWT_SECRET_KEY not set in environment! Using randomly generated key. "
            "This will break across server restarts. Set JWT_SECRET_KEY in production.",
            RuntimeWarning,
        )

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)

    # ============ DISTRIBUTED SERVER PORTS ============
    API_SERVER_PORT = int(os.environ.get("API_SERVER_PORT", 5001))
    GATEWAY_SERVER_PORT = int(os.environ.get("GATEWAY_SERVER_PORT", 5000))
    OPA_SERVER_PORT = int(os.environ.get("OPA_SERVER_PORT", 8181))
    OPA_AGENT_PORT = int(os.environ.get("OPA_AGENT_PORT", 8282))

    # ============ SERVICE COMMUNICATION URLs ============
    OPA_SERVER_URL = os.environ.get("OPA_SERVER_URL", "https://localhost:8181")
    API_SERVER_URL = os.environ.get("API_SERVER_URL", "https://localhost:5001")
    GATEWAY_SERVER_URL = os.environ.get("GATEWAY_SERVER_URL", "https://localhost:5000")
    OPA_AGENT_URL = os.environ.get("OPA_AGENT_URL", "https://localhost:8282")

    # Timeouts
    OPA_TIMEOUT = int(os.environ.get("OPA_TIMEOUT", 5))
    OPA_AGENT_TIMEOUT = int(os.environ.get("OPA_AGENT_TIMEOUT", 10))  # NEW
    SERVICE_TIMEOUT = int(os.environ.get("SERVICE_TIMEOUT", 10))

    # ============ SERVICE TOKENS ============
    SERVICE_TOKENS = {
        "gateway": os.environ.get("GATEWAY_SERVICE_TOKEN", "gateway-token-2024-zta"),
        "api": os.environ.get("API_SERVICE_TOKEN", "api-token-2024-zta"),
        "opa": os.environ.get("OPA_SERVICE_TOKEN", "opa-token-2024-zta"),
        "opa_agent": os.environ.get(
            "OPA_AGENT_TOKEN", "opa-agent-token-2024-zta"
        ),  # NEW
    }

    # Individual token access (for convenience)
    GATEWAY_SERVICE_TOKEN = SERVICE_TOKENS["gateway"]
    API_SERVICE_TOKEN = SERVICE_TOKENS["api"]
    OPA_SERVICE_TOKEN = SERVICE_TOKENS["opa"]
    OPA_AGENT_TOKEN = SERVICE_TOKENS["opa_agent"]  # NEW

    # ============ SERVICE COMMUNICATION SETTINGS ============
    SERVICE_MTLS_ENABLED = (
        os.environ.get("SERVICE_MTLS_ENABLED", "false").lower() == "true"
    )
    SERVICE_CERT_DIR = os.environ.get("SERVICE_CERT_DIR", "./certs/services")

    # Retry settings for service communication
    SERVICE_RETRY_ATTEMPTS = int(os.environ.get("SERVICE_RETRY_ATTEMPTS", 3))
    SERVICE_RETRY_DELAY = int(os.environ.get("SERVICE_RETRY_DELAY", 1))

    # ============ mTLS CONFIGURATION (For Gateway) ============
    SSL_CERT_PATH = os.environ.get("SSL_CERT_PATH", "./certs")
    MTLS_ENABLED = False  # Default to False, enable in production
    CA_CERT_PATH = os.path.join(SSL_CERT_PATH, "ca.crt")
    SERVER_CERT_PATH = os.path.join(SSL_CERT_PATH, "server.crt")
    SERVER_KEY_PATH = os.path.join(SSL_CERT_PATH, "server.key")

    # ============ ENCRYPTION CONFIGURATION ============  # NEW SECTION
    ENCRYPTION_ENABLED = os.environ.get("ENCRYPTION_ENABLED", "true").lower() == "true"
    RSA_KEY_SIZE = int(os.environ.get("RSA_KEY_SIZE", 2048))
    RSA_PUBLIC_EXPONENT = int(os.environ.get("RSA_PUBLIC_EXPONENT", 65537))

    # Key storage paths
    USER_KEYS_DIR = os.environ.get("USER_KEYS_DIR", "./certs/user_keys")
    OPA_AGENT_KEYS_DIR = os.environ.get("OPA_AGENT_KEYS_DIR", "./certs/opa_agent")

    # OPA Agent key files
    OPA_AGENT_PUBLIC_KEY_FILE = os.path.join(OPA_AGENT_KEYS_DIR, "public.pem")
    OPA_AGENT_PRIVATE_KEY_FILE = os.path.join(OPA_AGENT_KEYS_DIR, "private.pem")

    # Encryption algorithm
    ENCRYPTION_ALGORITHM = os.environ.get("ENCRYPTION_ALGORITHM", "RSA-OAEP-SHA256")
    NO_FALLBACK = True  # NO FALLBACK - if OPA Agent fails, access is denied

    # ============ SECURITY HEADERS ============
    SECURITY_HEADERS = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    }

    # ============ LOGGING ============
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.environ.get(
        "LOG_FORMAT",
        "%(asctime)s - %(name)s - %(levelname)s - [%(server)s] - %(message)s",
    )

    # ============ DISTRIBUTED TRACING ============
    TRACING_ENABLED = os.environ.get("TRACING_ENABLED", "true").lower() == "true"
    TRACE_HEADER_NAME = os.environ.get("TRACE_HEADER_NAME", "X-Request-ID")

    # ============ HEALTH CHECK SETTINGS ============
    HEALTH_CHECK_INTERVAL = int(os.environ.get("HEALTH_CHECK_INTERVAL", 30))
    HEALTH_CHECK_TIMEOUT = int(os.environ.get("HEALTH_CHECK_TIMEOUT", 5))

    # ============ RATE LIMITING (Gateway Only) ============
    RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "false").lower() == "true"
    RATE_LIMIT_REQUESTS = int(os.environ.get("RATE_LIMIT_REQUESTS", 100))
    RATE_LIMIT_PERIOD = int(os.environ.get("RATE_LIMIT_PERIOD", 60))  # seconds


class DevelopmentConfig(Config):
    DEBUG = True
    MTLS_ENABLED = True
    LOG_LEVEL = "DEBUG"
    TRACING_ENABLED = True
    ENCRYPTION_ENABLED = True  # Enable encryption in development



class ProductionConfig(Config):
    DEBUG = False
    MTLS_ENABLED = True

    # ENSURE all service tokens come from environment - NO DEFAULTS
    @property
    def API_SERVICE_TOKEN(self):
        token = os.environ.get("API_SERVICE_TOKEN")
        if not token:
            raise ValueError("CRITICAL: API_SERVICE_TOKEN must be set in environment!")
        return token

    @property
    def GATEWAY_SERVICE_TOKEN(self):
        token = os.environ.get("GATEWAY_SERVICE_TOKEN")
        if not token:
            raise ValueError(
                "CRITICAL: GATEWAY_SERVICE_TOKEN must be set in environment!"
            )
        return token

    @property
    def OPA_SERVICE_TOKEN(self):
        token = os.environ.get("OPA_SERVICE_TOKEN")
        if not token:
            raise ValueError("CRITICAL: OPA_SERVICE_TOKEN must be set in environment!")
        return token

    @property
    def OPA_AGENT_TOKEN(self):
        token = os.environ.get("OPA_AGENT_TOKEN")
        if not token:
            raise ValueError("CRITICAL: OPA_AGENT_TOKEN must be set in environment!")
        return token

    JWT_COOKIE_SECURE = True
    JWT_COOKIE_SAMESITE = "Strict"
    LOG_LEVEL = "WARNING"
    SERVICE_MTLS_ENABLED = True
    RATE_LIMIT_ENABLED = True
    ENCRYPTION_ENABLED = True
    NO_FALLBACK = True


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    MTLS_ENABLED = False
    SERVICE_MTLS_ENABLED = False
    LOG_LEVEL = "DEBUG"
    ENCRYPTION_ENABLED = False  # Disable encryption for testing
    NO_FALLBACK = True


config_dict = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
