# api_app.py - FULLY CORRECTED VERSION
"""
API Server Flask App Factory
"""

import os
from flask import Flask, request, jsonify, g
import json
import uuid
from datetime import datetime
from app import cors
from app.config import DevelopmentConfig
from app.api_models import db
from app.models.user import GovernmentDocument


def create_api_app(config_name="development"):
    """Create Flask app for API Server"""
    app = Flask(__name__)

    # Load configuration
    if config_name == "production":
        from app.config import ProductionConfig as ConfigClass
    else:
        ConfigClass = DevelopmentConfig

    app.config.from_object(ConfigClass)

    # Initialize extensions
    db.init_app(app)
    cors.init_app(app, origins=["https://localhost:5000", "http://localhost:5000"])

    # Get service tokens from environment
    API_SERVICE_TOKEN = os.environ.get("API_SERVICE_TOKEN")
    if not API_SERVICE_TOKEN:
        # Fallback to config for development
        API_SERVICE_TOKEN = app.config.get("API_SERVICE_TOKEN", "api-token-2024-zta")
        print(f"⚠️ API_SERVICE_TOKEN not in env, using config value")

    GATEWAY_SERVICE_TOKEN = app.config.get(
        "GATEWAY_SERVICE_TOKEN", "gateway-token-2024-zta"
    )
    OPA_AGENT_TOKEN = app.config.get("OPA_AGENT_TOKEN", "opa-agent-token-2024-zta")

    # ============ SINGLE BEFORE_REQUEST HANDLER ============
    @app.route("/", methods=["GET"])
    def root():
        """Block root access - return 403"""
        return (
            jsonify(
                {
                    "error": "Access Denied",
                    "message": "This API server can only be accessed through ZTA Gateway",
                }
            ),
            403,
        )

    @app.route("/", methods=["POST", "PUT", "DELETE"])
    def root_methods():
        """Block all methods on root"""
        return jsonify({"error": "Access Denied"}), 403

    @app.before_request
    def authenticate_and_authorize():
        """Single middleware for all requests - handles auth and access control"""

        # Allow CORS preflight
        if request.method == "OPTIONS":
            return

        # ============ HEALTH ENDPOINT ============
        if request.path == "/health":
            # Health endpoint: localhost only or with service token
            if request.remote_addr in ["127.0.0.1", "::1"]:
                return None

            service_token = request.headers.get("X-Service-Token")
            allowed_health_tokens = [
                API_SERVICE_TOKEN,
                GATEWAY_SERVICE_TOKEN,
                OPA_AGENT_TOKEN,
            ]

            if service_token and service_token in allowed_health_tokens:
                return None

            print(f"[SECURITY] Unauthorized health check from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 401

        # ============ ALL OTHER ENDPOINTS ============
        # Require valid service token from Gateway OR OPA Agent
        service_token = request.headers.get("X-Service-Token")

        # List of allowed callers
        allowed_tokens = [
            API_SERVICE_TOKEN,
            GATEWAY_SERVICE_TOKEN,  # Gateway calling API Server
            OPA_AGENT_TOKEN,  # OPA Agent calling API Server
        ]

        if not service_token or service_token not in allowed_tokens:
            print(
                f"[SECURITY] Blocked direct access to {request.path} from {request.remote_addr}"
            )
            print(
                f"  Token provided: {service_token[:20] if service_token else 'None'}..."
            )
            return (
                jsonify(
                    {
                        "error": "Access Denied",
                        "message": "This endpoint can only be accessed through ZTA Gateway",
                        "zta_context": {
                            "required": "Valid service token from Gateway or OPA Agent",
                            "your_ip": request.remote_addr,
                        },
                    }
                ),
                403,
            )

        # ============ EXTRACT USER CLAIMS (from Gateway) ============
        user_claims_json = request.headers.get("X-User-Claims")
        if user_claims_json:
            try:
                g.user_claims = json.loads(user_claims_json)
                print(
                    f"[API] Processing request for user: {g.user_claims.get('username')}"
                )
            except json.JSONDecodeError as e:
                print(f"[ERROR] Failed to parse user claims: {e}")
                return jsonify({"error": "Invalid user claims"}), 400

        # Generate/forward request ID for tracing
        g.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

        return None

    # Handle CORS after request
    @app.after_request
    def after_request(response):
        response.headers.add("Access-Control-Allow-Origin", "https://localhost:5000")
        response.headers.add(
            "Access-Control-Allow-Headers",
            "Content-Type, X-Service-Token, X-Request-ID, Authorization, X-User-Claims",
        )
        response.headers.add(
            "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"
        )
        response.headers.add("Access-Control-Allow-Credentials", "true")
        return response

    # ============ REGISTER BLUEPRINTS ============
    from app.api.api_routes import api_bp
    from app.auth.routes import auth_bp
    from app.api.registration import registration_bp

    # ============ ADD RESOURCES ENDPOINT ============
    @api_bp.route("/resources", methods=["GET"])
    def get_resources_api():
        """Get resources from database for API calls"""
        try:
            user_claims = g.get("user_claims", {})
            if not user_claims:
                return jsonify({"error": "User claims required"}), 400

            user_department = user_claims.get("department")
            user_clearance = user_claims.get("clearance_level", "BASIC")
            current_hour = datetime.now().hour

            documents = GovernmentDocument.query.filter_by(is_archived=False).all()

            classification_map = {
                "PUBLIC": "PUBLIC",
                "DEPARTMENT": "DEPARTMENT",
                "TOP_SECRET": "TOP_SECRET",
                "CONFIDENTIAL": "DEPARTMENT",
                "SECRET": "DEPARTMENT",
            }

            filtered_resources = []
            for doc in documents:
                tier = classification_map.get(doc.classification, "PUBLIC")

                if tier == "PUBLIC":
                    filtered_resources.append(
                        {
                            "id": doc.id,
                            "name": doc.title,
                            "tier": "PUBLIC",
                            "department": doc.department,
                            "description": doc.description,
                        }
                    )
                elif tier == "DEPARTMENT" and doc.department == user_department:
                    filtered_resources.append(
                        {
                            "id": doc.id,
                            "name": doc.title,
                            "tier": "DEPARTMENT",
                            "department": doc.department,
                            "description": doc.description,
                        }
                    )
                elif tier == "TOP_SECRET" and doc.department == user_department:
                    if user_clearance in ["SECRET", "TOP_SECRET"]:
                        if 8 <= current_hour < 16:
                            filtered_resources.append(
                                {
                                    "id": doc.id,
                                    "name": doc.title,
                                    "tier": "TOP_SECRET",
                                    "department": doc.department,
                                    "description": doc.description,
                                }
                            )
                        else:
                            filtered_resources.append(
                                {
                                    "id": doc.id,
                                    "name": f"🔒 {doc.title} (Available 8 AM - 4 PM)",
                                    "tier": "TOP_SECRET",
                                    "department": doc.department,
                                    "restricted": True,
                                }
                            )

            return jsonify(
                {
                    "resources": filtered_resources,
                    "user_info": {
                        "department": user_department,
                        "clearance": user_clearance,
                        "current_hour": current_hour,
                    },
                    "zta_context": {
                        "server": "api_server",
                        "request_id": g.get("request_id", "unknown"),
                    },
                }
            )

        except Exception as e:
            return (
                jsonify({"error": "Failed to fetch resources", "message": str(e)}),
                500,
            )

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(registration_bp, url_prefix="/api/register")
    app.register_blueprint(api_bp, url_prefix="/api")

    # ============ HEALTH ENDPOINT ============
    @app.route("/health", methods=["GET"])
    def health():
        """Health check - requires service token or localhost"""
        # Check localhost
        if request.remote_addr in ["127.0.0.1", "::1"]:
            return jsonify(
                {
                    "status": "healthy",
                    "server": "api_server",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

        # Check service token
        service_token = request.headers.get("X-Service-Token")
        expected_token = os.environ.get("API_SERVICE_TOKEN") or app.config.get(
            "API_SERVICE_TOKEN"
        )

        if service_token and service_token == expected_token:
            return jsonify(
                {
                    "status": "healthy",
                    "server": "api_server",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )

        return jsonify({"error": "Unauthorized"}), 401

    # Create tables
    with app.app_context():
        db.create_all()
        print("✅ API Server: Database initialized")

    print("\n" + "=" * 60)
    print(" API SERVER WITH SECURITY MIDDLEWARE")
    print("=" * 60)
    print(" Port: 5001")
    print(" Allowed Callers: Gateway, OPA Agent")
    print(" Health: Service token or localhost only")
    print("=" * 60)

    return app
