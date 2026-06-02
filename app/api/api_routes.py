"""
API Server Routes - Business logic only
No authentication decorators - gateway handles authentication
"""

from flask import Blueprint, request, jsonify, current_app, g
from app.api_models import db, User, GovernmentDocument, AccessLog
from app.logs.zta_event_logger import event_logger, EventType, Severity
from app.logs.request_tracker import log_request
from app.logs.zta_event_logger import event_logger, EventType
from datetime import datetime
from functools import wraps
import uuid
import json

api_bp = Blueprint("api", __name__)


def require_service_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        service_token = request.headers.get("X-Service-Token")
        expected_token = current_app.config.get("API_SERVICE_TOKEN")

        if not service_token or service_token != expected_token:
            # Allow localhost for internal calls
            if request.remote_addr not in ["127.0.0.1", "::1"]:
                return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)

    return decorated_function


@api_bp.route("/documents", methods=["GET"])
def get_documents():
    """Get documents - called by gateway after auth"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 400

        user_id = user_claims.get("sub")
        user_class = user_claims.get("user_class")
        user_facility = user_claims.get("facility")
        user_department = user_claims.get("department")

        # Build query
        query = GovernmentDocument.query.filter_by(
            facility=user_facility, is_archived=False
        )

        # Apply department filter for regular users
        if user_class in ["user", "admin"]:
            query = query.filter_by(department=user_department)

        # Get query parameters
        classification = request.args.get("classification")
        department = request.args.get("department")
        category = request.args.get("category")
        search = request.args.get("search")

        if classification:
            query = query.filter_by(classification=classification)
        if department:
            query = query.filter_by(department=department)
        if category:
            query = query.filter_by(category=category)
        if search:
            query = query.filter(
                db.or_(
                    GovernmentDocument.title.ilike(f"%{search}%"),
                    GovernmentDocument.description.ilike(f"%{search}%"),
                )
            )

        documents = query.order_by(GovernmentDocument.created_at.desc()).all()

        # Log access
        log_request(
            user_id=user_id,
            endpoint="/api/documents",
            method="GET",
            status="allowed",
            reason="Gateway forwarded request",
            auth_method=user_claims.get("auth_method", "unknown"),
            request_id=g.request_id,
        )

        return (
            jsonify(
                {
                    "documents": [doc.to_dict() for doc in documents],
                    "zta_context": {
                        "server": "api_server",
                        "request_id": g.request_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch documents", "message": str(e)}), 500


@api_bp.route("/documents/<int:document_id>", methods=["GET"])
def get_document(document_id):
    """Get single document - called by gateway after auth"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 400

        document = GovernmentDocument.query.get(document_id)

        if not document:
            return jsonify({"error": "Document not found"}), 404

        # Return as resource format for consistency
        return (
            jsonify(
                {
                    "id": document.id,
                    "name": document.title,
                    "title": document.title,
                    "description": document.description,
                    "content": document.content,
                    "tier": document.classification,
                    "department": document.department,
                    "facility": document.facility,
                    "category": document.category,
                    "document_id": document.document_id,
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch document", "message": str(e)}), 500


@api_bp.route("/api/internal/encrypt-for-user", methods=["POST"])
def encrypt_for_user():
    """
    PURE ENCRYPTION ENDPOINT - NO FALLBACKS
    If this fails, access is DENIED - that's the security model
    """
    try:
        # 1. Validate service token (strict)
        service_token = request.headers.get("X-Service-Token")
        expected_token = current_app.config.get("API_SERVICE_TOKEN")

        if not service_token or service_token != expected_token:
            # Log security violation
            event_logger.log_event(
                event_type=EventType.SECURITY_VIOLATION,
                source_component="api_server",
                action="Invalid service token",
                details={
                    "ip": request.remote_addr,
                    "endpoint": "/api/internal/encrypt-for-user",
                },
                severity=Severity.HIGH,
            )
            return jsonify({"error": "Security violation - invalid service token"}), 401

        # 2. Get and validate request data
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400

        user_id = data.get("user_id")
        data_to_encrypt = data.get("data")

        if not user_id or not data_to_encrypt:
            return jsonify({"error": "Missing user_id or data"}), 400

        # 3. Get user's public key from database
        from app.models.user import User

        user = User.query.get(user_id)

        if not user:
            # Log missing user
            event_logger.log_event(
                event_type=EventType.SECURITY_VIOLATION,
                source_component="api_server",
                action="User not found during encryption",
                user_id=user_id,
                severity=Severity.HIGH,
            )
            return jsonify({"error": "User not found"}), 404

        if not user.public_key:
            # Log missing key
            event_logger.log_event(
                event_type=EventType.ENCRYPTION_FAILED,
                source_component="api_server",
                action="User public key missing",
                user_id=user_id,
                severity=Severity.HIGH,
            )
            return jsonify({"error": "User public key not found - cannot encrypt"}), 400

        # 4. Use crypto handler for encryption
        from app.opa_agent.crypto_handler import CryptoHandler

        crypto = CryptoHandler()

        # 5. Attempt encryption - if this fails, access DENIED
        try:
            encrypted = crypto.encrypt_for_user(
                data=data_to_encrypt, user_public_key_pem=user.public_key
            )
        except Exception as e:
            # Log encryption failure
            event_logger.log_event(
                event_type=EventType.ENCRYPTION_FAILED,
                source_component="api_server",
                action="Encryption failed",
                user_id=user_id,
                details={"error": str(e)},
                severity=Severity.HIGH,
            )
            return jsonify({"error": "Encryption failed - access denied"}), 500

        # 6. Verify encryption actually worked
        if not encrypted or len(encrypted) < 10:
            return jsonify({"error": "Encryption produced invalid result"}), 500

        # 7. Log successful encryption
        event_logger.log_event(
            event_type=EventType.ENCRYPTION_SUCCESS,
            source_component="api_server",
            action="Data encrypted for user",
            user_id=user_id,
            details={"data_size": len(str(data_to_encrypt))},
            severity=Severity.INFO,
        )

        # 8. Return ONLY encrypted data - never plaintext
        return (
            jsonify(
                {
                    "encrypted_data": encrypted,
                    "algorithm": "RSA-OAEP-SHA256",
                    "key_size": 2048,
                }
            ),
            200,
        )

    except Exception as e:
        # Log any unexpected errors
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="api_server",
            action="Unexpected error in encryption endpoint",
            details={"error": str(e)},
            severity=Severity.HIGH,
        )
        return jsonify({"error": "Internal server error - access denied"}), 500


@api_bp.route("/documents", methods=["POST"])
def create_document():
    """Create document - called by gateway after auth"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 400

        user_id = user_claims.get("sub")
        user_facility = user_claims.get("facility")
        user_department = user_claims.get("department")

        data = request.get_json()

        # Generate document ID
        document_id = f"{user_facility[:3].upper()}-{user_department[:3].upper()}-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"

        # Create document
        new_document = GovernmentDocument(
            document_id=document_id,
            title=data["title"],
            description=data.get("description", ""),
            content=data.get("content", ""),
            classification=data["classification"],
            facility=user_facility,
            department=user_department,
            category=data["category"],
            owner_id=user_id,
            created_by=user_id,
        )

        db.session.add(new_document)
        db.session.commit()

        return (
            jsonify(
                {
                    "message": "Document created successfully",
                    "document": {
                        "id": new_document.id,
                        "document_id": new_document.document_id,
                        "title": new_document.title,
                    },
                    "zta_context": {
                        "server": "api_server",
                        "request_id": g.request_id,
                    },
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "Failed to create document", "message": str(e)}), 500


@api_bp.route("/users", methods=["GET"])
def get_users():
    """Get users - called by gateway after auth"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 400

        user_class = user_claims.get("user_class")
        user_facility = user_claims.get("facility")

        # Only admin and superadmin can access user list
        if user_class not in ["admin", "superadmin"]:
            return jsonify({"error": "Admin access required"}), 403

        # Build query
        query = User.query.filter_by(facility=user_facility)

        # Apply filters
        department = request.args.get("department")
        user_class_filter = request.args.get("user_class")

        if department:
            query = query.filter_by(department=department)
        if user_class_filter:
            query = query.filter_by(user_class=user_class_filter)

        users = query.order_by(User.created_at.desc()).all()

        return (
            jsonify(
                {
                    "users": [user.to_dict() for user in users],
                    "total": len(users),
                    "zta_context": {
                        "server": "api_server",
                        "request_id": g.request_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch users", "message": str(e)}), 500


@api_bp.route("/logs", methods=["GET"])
def get_logs():
    """Get access logs - called by gateway after auth"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 400

        user_class = user_claims.get("user_class")
        user_facility = user_claims.get("facility")

        # Only admin and superadmin can access logs
        if user_class not in ["admin", "superadmin"]:
            return jsonify({"error": "Admin access required"}), 403

        # Build query
        query = AccessLog.query.join(User).filter(User.facility == user_facility)

        # Apply filters
        user_filter = request.args.get("user_id", type=int)
        document_filter = request.args.get("document_id", type=int)

        if user_filter and user_class == "superadmin":
            query = query.filter(AccessLog.user_id == user_filter)
        if document_filter:
            query = query.filter(AccessLog.document_id == document_filter)

        limit = request.args.get("limit", 100, type=int)
        logs = query.order_by(AccessLog.timestamp.desc()).limit(limit).all()

        return (
            jsonify(
                {
                    "logs": [
                        {
                            "id": log.id,
                            "user_id": log.user_id,
                            "username": log.user.username if log.user else "Unknown",
                            "document_id": log.document_id,
                            "action": log.action,
                            "timestamp": log.timestamp.isoformat(),
                            "status": log.status,
                            "reason": log.reason,
                        }
                        for log in logs
                    ],
                    "total": len(logs),
                    "zta_context": {
                        "server": "api_server",
                        "request_id": g.request_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch logs", "message": str(e)}), 500


@api_bp.route("/documents/stats", methods=["GET"])
def get_dashboard_stats():
    """Get dashboard statistics - called by gateway after auth"""
    try:
        user_claims = g.get("user_claims", {})
        if not user_claims:
            return jsonify({"error": "User claims required"}), 400

        user_id = user_claims.get("sub")

        # Count user's documents
        user_doc_count = GovernmentDocument.query.filter_by(owner_id=user_id).count()

        # Count today's accesses
        today = datetime.utcnow().date()
        today_accesses = AccessLog.query.filter(
            AccessLog.user_id == user_id, db.func.date(AccessLog.timestamp) == today
        ).count()

        return (
            jsonify(
                {
                    "your_documents": user_doc_count,
                    "today_accesses": today_accesses,
                    "zta_context": {
                        "server": "api_server",
                        "request_id": g.request_id,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to fetch stats", "message": str(e)}), 500


# Internal endpoints for Gateway Server
@api_bp.route("/internal/validate-user", methods=["POST"])
def validate_user():
    """Internal endpoint for Gateway to validate user credentials"""
    from app.models.user import User
    from flask import request, jsonify

    data = request.get_json()

    # Verify service token
    service_token = request.headers.get("X-Service-Token")
    expected_token = current_app.config.get("API_SERVICE_TOKEN", "api-token-2024")

    if service_token != expected_token:
        return jsonify({"error": "Invalid service token"}), 403

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing credentials"}), 400

    # Find user
    user = User.query.filter_by(username=username).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.check_password(password):
        return jsonify({"error": "Invalid password"}), 401

    return jsonify({"success": True, "user": user.to_dict()}), 200


@api_bp.route("/internal/validate-user-id", methods=["POST"])
def validate_user_id():
    """Internal endpoint for Gateway to validate user by ID"""
    from app.models.user import User
    from flask import request, jsonify

    data = request.get_json()

    # Verify service token
    service_token = request.headers.get("X-Service-Token")
    expected_token = current_app.config.get("API_SERVICE_TOKEN", "api-token-2024")

    if service_token != expected_token:
        return jsonify({"error": "Invalid service token"}), 403

    user_id = data.get("user_id")

    if not user_id:
        return jsonify({"error": "Missing user ID"}), 400

    # Find user
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    if not user.is_active:
        return jsonify({"error": "User inactive"}), 403

    return jsonify({"success": True, "user": user.to_dict()}), 200
