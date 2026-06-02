"""
ZTA API Server - Business logic and database operations
Only accepts requests from Gateway with valid service tokens
Uses centralized SSL config
"""
from dotenv import load_dotenv
load_dotenv() 
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import centralized SSL config
try:
    from app.ssl_config import create_ssl_context

    HAS_SSL_CONFIG = True
except ImportError:
    HAS_SSL_CONFIG = False

from app.logs.zta_event_logger import event_logger, EventType, Severity
from app.api_app import create_api_app

# Create the app
app = create_api_app()

if __name__ == "__main__":
    print("=" * 60)
    print("ZTA API SERVER")
    print("=" * 60)
    print(f"Port: {app.config.get('API_SERVER_PORT', 5001)}")
    print("Authentication: Service tokens only")
    print(
        f"Service Token: {app.config.get('API_SERVICE_TOKEN', 'api-token-2024')[:10]}..."
    )
    print("=" * 60)

    # Use centralized SSL config if available
    if HAS_SSL_CONFIG:
        ssl_context = create_ssl_context(verify_client=False)
    else:
        # Fallback
        ssl_context = ("certs/server.crt", "certs/server.key")

    app.run(
        debug=True,
        host="127.0.0.1",
        port=app.config.get("API_SERVER_PORT", 5001),
        ssl_context=ssl_context,
        use_reloader=False,  # Add this to prevent socket issues
    )
