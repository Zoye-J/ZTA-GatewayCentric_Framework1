from flask import Blueprint, request, jsonify, current_app, g
from app.mTLS.middleware import require_authentication, require_mtls
from app.logs.zta_event_logger import event_logger, EventType, Severity
from datetime import datetime
import uuid
import hashlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from app import db
from app.models.user import GovernmentDocument, AccessLog, User
from functools import wraps

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


# KEEP: Simple ZTA test endpoint (for gateway)
@api_bp.route("/zta-test", methods=["GET"])
def simple_zta_test():
    """
    Simple ZTA test endpoint - no authentication required
    Just checks if certificate is present (gateway functionality)
    """
    request_id = str(uuid.uuid4())

    # Check for certificate
    cert_pem = request.environ.get("SSL_CLIENT_CERT")

    if cert_pem:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            fingerprint = cert.fingerprint(hashlib.sha256()).hex()

            # Extract info
            email = None
            for attr in cert.subject:
                if attr.oid._name == "emailAddress":
                    email = attr.value
                    break
                elif attr.oid._name == "commonName" and "@" in attr.value:
                    email = attr.value

            # Log mTLS certificate detection
            event_logger.log_event(
                event_type=EventType.MTLS_HANDSHAKE,
                source_component="gateway",
                action="mTLS certificate validated",
                source_ip=request.remote_addr or "127.0.0.1",
                details={
                    "certificate_present": True,
                    "email": email,
                    "fingerprint_short": fingerprint[:16] + "...",
                    "test_endpoint": True,
                },
                trace_id=request_id,
                severity=Severity.INFO,
            )

            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "mTLS certificate detected",
                        "certificate": {
                            "present": True,
                            "email": email,
                            "fingerprint_short": fingerprint[:16] + "...",
                            "subject": {
                                attr.oid._name: attr.value for attr in cert.subject
                            },
                        },
                        "zta_info": {
                            "authentication_method": "mTLS",
                            "layer": "Transport security",
                        },
                    }
                ),
                200,
            )
        except Exception as e:
            event_logger.log_event(
                event_type=EventType.CLIENT_CERT_INVALID,
                source_component="gateway",
                action="Certificate error",
                source_ip=request.remote_addr or "127.0.0.1",
                details={
                    "error": str(e),
                    "certificate_present": True,
                },
                trace_id=request_id,
                severity=Severity.HIGH,
            )
            return (
                jsonify(
                    {
                        "status": "error",
                        "message": f"Certificate error: {str(e)}",
                        "certificate": {"present": True, "valid": False},
                    }
                ),
                400,
            )

    # No certificate
    event_logger.log_event(
        event_type=EventType.CLIENT_CERT_INVALID,
        source_component="gateway",
        action="No client certificate provided",
        source_ip=request.remote_addr or "127.0.0.1",
        details={
            "reason": "No client certificate provided",
            "test_endpoint": True,
        },
        trace_id=request_id,
        severity=Severity.MEDIUM,
    )

    return (
        jsonify(
            {
                "status": "info",
                "message": "No client certificate provided",
                "certificate": {"present": False},
                "hint": "Connect with: curl --cert ./certs/clients/1/client.crt --key ./certs/clients/1/client.key --cacert ./certs/ca.crt https://localhost:8443/api/zta-test",
            }
        ),
        200,
    )


# KEEP: Test authentication endpoint (for gateway)
@api_bp.route("/zta/test", methods=["GET"])
@require_authentication
def test_zta_auth():
    """Test Zero Trust Authentication (JWT + mTLS) - Gateway test"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        # Get auth method from g object (set by middleware)
        auth_method = getattr(g, "auth_method", "unknown")
        user_id = getattr(g, "jwt_identity", None)

        if auth_method == "mtls":
            cert_info = getattr(g, "client_certificate", {})
            email = cert_info.get("subject", {}).get("emailAddress", "Unknown")

            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "Zero Trust Authentication successful",
                        "authentication_layers": {
                            "layer1_mtls": "✓ Client certificate validated",
                            "layer2_jwt": "✗ JWT token not required (mTLS only)",
                        },
                        "certificate_info": {
                            "fingerprint": cert_info.get("fingerprint", "")[:16]
                            + "...",
                            "subject": cert_info.get("subject", {}),
                        },
                        "auth_method": "mTLS",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                ),
                200,
            )

        elif auth_method == "jwt":
            return (
                jsonify(
                    {
                        "status": "success",
                        "message": "JWT Authentication successful",
                        "authentication_layers": {
                            "layer1_mtls": "✗ Client certificate not present",
                            "layer2_jwt": "✓ JWT token validated",
                        },
                        "auth_method": "JWT",
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                ),
                200,
            )

        else:
            return jsonify({"error": "Authentication required"}), 401

    except Exception as e:
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="gateway",
            action="ZTA test error",
            details={
                "error": str(e),
                "test_endpoint": True,
            },
            trace_id=getattr(g, "request_id", str(uuid.uuid4())),
            severity=Severity.MEDIUM,
        )
        return jsonify({"error": "ZTA test failed", "message": str(e)}), 500


# KEEP: Service health endpoint (for gateway)
@api_bp.route("/service/health", methods=["GET"])
@require_service_token
@require_mtls  # Services only need mTLS
def service_health():
    """Service health check - mTLS only (service-to-service)"""
    request_id = str(uuid.uuid4())
    auth_method = getattr(g, "auth_method", "unknown")

    return jsonify(
        {
            "status": "healthy",
            "service": "ZTA Gateway Server",
            "auth_method": auth_method,
            "timestamp": datetime.utcnow().isoformat(),
            "zta_enabled": True,
            "features": ["JWT", "mTLS", "OPA", "Certificate Validation", "RBAC"],
            "access_restriction": "mTLS certificate required for services",
            "request_id": request_id,
        }
    )


# KEEP: Certificate verification logging endpoint (for gateway)
@api_bp.route("/certificate/verify", methods=["POST"])
@require_mtls  # Requires mTLS certificate
def verify_certificate():
    """Endpoint to verify and log certificate details (gateway functionality)"""
    try:
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        # Get certificate from g object
        if not hasattr(g, "client_certificate"):
            return jsonify({"error": "No certificate provided"}), 400

        cert_info = g.client_certificate

        return (
            jsonify(
                {
                    "status": "success",
                    "certificate_valid": True,
                    "certificate_details": cert_info,
                    "zta_context": {
                        "verification_method": "mTLS_certificate",
                        "request_id": request_id,
                        "timestamp": datetime.utcnow().isoformat(),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        event_logger.log_event(
            event_type=EventType.ERROR,
            source_component="gateway",
            action="Certificate verification error",
            source_ip=request.remote_addr or "127.0.0.1",
            details={
                "error": str(e),
            },
            trace_id=getattr(g, "request_id", str(uuid.uuid4())),
            severity=Severity.HIGH,
        )
        return (
            jsonify({"error": "Certificate verification failed", "message": str(e)}),
            500,
        )


@api_bp.route("/resources", methods=["GET"])
@require_authentication
def get_resources():
    """Get all resources visible to the user - FIXED VERSION"""
    try:
        user = g.current_user
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        # Get all non-archived documents
        all_documents = GovernmentDocument.query.filter_by(is_archived=False).all()

        accessible_documents = []

        for doc in all_documents:
            doc_dict = doc.to_dict()

            # Add classification to match OPA policy expectations
            # Map database classifications to OPA expected classifications
            classification_map = {
                "PUBLIC": "BASIC",
                "DEPARTMENT": "CONFIDENTIAL",
                "TOP_SECRET": "TOP_SECRET",
            }

            doc_dict["classification"] = classification_map.get(
                doc.classification, "BASIC"
            )
            doc_dict["type"] = "document"
            doc_dict["action"] = "read"

            accessible_documents.append(doc_dict)

        return jsonify(accessible_documents), 200

    except Exception as e:
        current_app.logger.error(f"Error getting resources: {str(e)}")
        return jsonify({"error": "Failed to get resources"}), 500


@api_bp.route("/resources/<int:resource_id>/access", methods=["POST"])
@require_authentication
def request_resource_access(resource_id):
    """Request access to a specific resource"""
    try:
        user = g.current_user
        request_id = getattr(g, "request_id", str(uuid.uuid4()))

        # Get the resource
        resource = GovernmentDocument.query.get_or_404(resource_id)

        # Log the access attempt
        access_log = AccessLog(
            user_id=user.id,
            document_id=resource_id,
            action="request_access",
            timestamp=datetime.utcnow(),
            status="pending",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string if request.user_agent else None,
            request_id=request_id,
            event_type="RESOURCE_ACCESS_REQUEST",
        )
        db.session.add(access_log)

        # Check access rules
        current_hour = datetime.utcnow().hour

        # PUBLIC - auto approve
        if resource.classification == "PUBLIC":
            access_log.status = "allowed"
            access_log.reason = "Public resource - auto approved"
            db.session.commit()
            return (
                jsonify(
                    {
                        "access_granted": True,
                        "message": "Access granted to public resource",
                        "resource": resource.to_dict(),
                    }
                ),
                200,
            )

        # DEPARTMENT - auto approve if same department
        if resource.classification == "DEPARTMENT":
            if user.department == resource.department:
                access_log.status = "allowed"
                access_log.reason = f"Same department access - {user.department}"
                db.session.commit()
                return (
                    jsonify(
                        {
                            "access_granted": True,
                            "message": f"Access granted to {resource.department} resource",
                            "resource": resource.to_dict(),
                        }
                    ),
                    200,
                )
            else:
                access_log.status = "denied"
                access_log.reason = f"Wrong department. User: {user.department}, Required: {resource.department}"
                db.session.commit()
                return (
                    jsonify(
                        {
                            "access_granted": False,
                            "message": f"Access denied: Department restricted ({resource.department} only)",
                        }
                    ),
                    403,
                )

        # TOP_SECRET - check multiple conditions
        if resource.classification == "TOP_SECRET":
            # 1. Must be MOD department
            if resource.department != "MOD":
                access_log.status = "denied"
                access_log.reason = "TOP_SECRET resources are MOD department only"
                db.session.commit()
                return (
                    jsonify(
                        {
                            "access_granted": False,
                            "message": "TOP_SECRET resources are for MOD department only",
                        }
                    ),
                    403,
                )

            # 2. User must be MOD with TOP_SECRET clearance
            if user.department != "MOD" or user.clearance_level != "TOP_SECRET":
                access_log.status = "denied"
                access_log.reason = f"User department/clearance mismatch. Dept: {user.department}, Clearance: {user.clearance_level}"
                db.session.commit()
                return (
                    jsonify(
                        {
                            "access_granted": False,
                            "message": "MOD department with TOP_SECRET clearance required",
                        }
                    ),
                    403,
                )

            # 3. Check time restrictions (8 AM - 4 PM local time)
            # Note: This is UTC hour check, adjust for local timezone if needed
            if current_hour < 8 or current_hour >= 16:
                access_log.status = "denied"
                access_log.reason = (
                    f"Time restricted. Current hour: {current_hour} (8-16 required)"
                )
                db.session.commit()
                return (
                    jsonify(
                        {
                            "access_granted": False,
                            "requires_approval": True,
                            "message": "TOP_SECRET access restricted to business hours (8 AM - 4 PM)",
                        }
                    ),
                    403,
                )

            # 4. If all checks pass
            access_log.status = "allowed"
            access_log.reason = "TOP_SECRET access granted during business hours"
            db.session.commit()
            return (
                jsonify(
                    {
                        "access_granted": True,
                        "message": "TOP_SECRET access granted",
                        "resource": resource.to_dict(),
                    }
                ),
                200,
            )

        # Default deny
        access_log.status = "denied"
        access_log.reason = "Access denied by default policy"
        db.session.commit()
        return jsonify({"access_granted": False, "message": "Access denied"}), 403

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error requesting resource access: {str(e)}")
        return jsonify({"error": "Failed to process access request"}), 500


@api_bp.route("/resources/create-sample", methods=["POST"])
@require_authentication
def create_sample_resources():
    """Create sample resources for testing (admin only)"""
    try:
        user = g.current_user

        # Only admins can create sample data
        if user.user_class not in ["admin", "superadmin"]:
            return jsonify({"error": "Admin access required"}), 403

        # Sample resources data
        sample_resources = [
            # PUBLIC resources (all departments can see)
            {
                "document_id": "GOV-PUB-001",
                "title": "Government Annual Report 2024",
                "description": "Public annual report of government activities",
                "content": "Annual report content...",
                "classification": "PUBLIC",
                "facility": "Government HQ",
                "department": "GENERAL",
                "category": "Reports",
                "owner_id": user.id,
                "created_by": user.id,
            },
            {
                "document_id": "GOV-PUB-002",
                "title": "Public Service Announcements",
                "description": "Latest public service announcements",
                "content": "PSA content...",
                "classification": "PUBLIC",
                "facility": "Government HQ",
                "department": "GENERAL",
                "category": "Announcements",
                "owner_id": user.id,
                "created_by": user.id,
            },
            # MOD Department resources
            {
                "document_id": "MOD-DEP-001",
                "title": "Military Readiness Report",
                "description": "Current military readiness status",
                "content": "Military readiness content...",
                "classification": "DEPARTMENT",
                "facility": "Ministry of Defense",
                "department": "MOD",
                "category": "Military",
                "owner_id": user.id,
                "created_by": user.id,
            },
            {
                "document_id": "MOD-DEP-002",
                "title": "Defense Budget Allocation",
                "description": "Quarterly defense budget allocation",
                "content": "Budget content...",
                "classification": "DEPARTMENT",
                "facility": "Ministry of Defense",
                "department": "MOD",
                "category": "Budget",
                "owner_id": user.id,
                "created_by": user.id,
            },
            # MOF Department resources
            {
                "document_id": "MOF-DEP-001",
                "title": "National Budget Proposal",
                "description": "Proposed national budget for next fiscal year",
                "content": "Budget proposal content...",
                "classification": "DEPARTMENT",
                "facility": "Ministry of Finance",
                "department": "MOF",
                "category": "Budget",
                "owner_id": user.id,
                "created_by": user.id,
            },
            {
                "document_id": "MOF-DEP-002",
                "title": "Tax Revenue Analysis",
                "description": "Analysis of national tax revenue collection",
                "content": "Tax analysis content...",
                "classification": "DEPARTMENT",
                "facility": "Ministry of Finance",
                "department": "MOF",
                "category": "Finance",
                "owner_id": user.id,
                "created_by": user.id,
            },
            # NSA Department resources
            {
                "document_id": "NSA-DEP-001",
                "title": "Cybersecurity Threat Assessment",
                "description": "Latest cybersecurity threat assessment",
                "content": "Threat assessment content...",
                "classification": "DEPARTMENT",
                "facility": "National Security Agency",
                "department": "NSA",
                "category": "Security",
                "owner_id": user.id,
                "created_by": user.id,
            },
            {
                "document_id": "NSA-DEP-002",
                "title": "Intelligence Briefing",
                "description": "Daily intelligence briefing",
                "content": "Intelligence content...",
                "classification": "DEPARTMENT",
                "facility": "National Security Agency",
                "department": "NSA",
                "category": "Intelligence",
                "owner_id": user.id,
                "created_by": user.id,
            },
            # MOD TOP SECRET resources
            {
                "document_id": "MOD-TS-001",
                "title": "TOP SECRET: Special Operations Plan",
                "description": "Detailed plan for special military operations",
                "content": "TOP SECRET content...",
                "classification": "TOP_SECRET",
                "facility": "Ministry of Defense",
                "department": "MOD",
                "category": "Operations",
                "owner_id": user.id,
                "created_by": user.id,
            },
            {
                "document_id": "MOD-TS-002",
                "title": "TOP SECRET: Advanced Weapons Research",
                "description": "Research on advanced military weapons systems",
                "content": "Research content...",
                "classification": "TOP_SECRET",
                "facility": "Ministry of Defense",
                "department": "MOD",
                "category": "Research",
                "owner_id": user.id,
                "created_by": user.id,
            },
        ]

        created_count = 0
        for resource_data in sample_resources:
            # Check if document already exists
            existing = GovernmentDocument.query.filter_by(
                document_id=resource_data["document_id"]
            ).first()

            if not existing:
                doc = GovernmentDocument(**resource_data)
                db.session.add(doc)
                created_count += 1

        db.session.commit()

        return (
            jsonify(
                {
                    "message": f"Created {created_count} sample resources",
                    "total_samples": len(sample_resources),
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error creating sample resources: {str(e)}")
        return jsonify({"error": "Failed to create sample resources"}), 500
