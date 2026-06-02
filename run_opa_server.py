#!/usr/bin/env python3
"""
Python OPA Server for ZTA Thesis - FIXED VERSION
Serves as policy decision engine
"""

import sys
import os
import json
import time
import ssl
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class OPAHandler(BaseHTTPRequestHandler):
    """Simple OPA policy server handler - NO EXTERNAL DEPENDENCIES"""

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        if self.path == "/health":
            self._send_json(
                {
                    "status": "healthy",
                    "server": "OPA Policy Server",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        elif self.path == "/v1/policies":
            self._send_json(
                {"policies": ["zta/allow", "zta/time_based"], "status": "loaded"}
            )
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/v1/data/zta/allow":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                post_data = self.rfile.read(content_length)
                body = json.loads(post_data)

                opa_input = body.get("input", {})
                result = self._evaluate_policy(opa_input)

                self._send_json(result)
            except Exception as e:
                self._send_json({"result": False, "reason": str(e)}, 500)
        else:
            self.send_response(404)
            self.end_headers()

    def _evaluate_policy(self, opa_input):
        """Evaluate ZTA policy"""
        user = opa_input.get("user", {})
        resource = opa_input.get("resource", {})
        environment = opa_input.get("environment", {})

        user_clearance = user.get("clearance", "BASIC")
        resource_class = resource.get("classification", "BASIC")
        user_dept = user.get("department", "")
        resource_dept = resource.get("department", "")
        current_hour = environment.get("current_hour", datetime.now().hour)

        # Clearance hierarchy
        clearance_levels = {
            "BASIC": 1,
            "CONFIDENTIAL": 2,
            "SECRET": 3,
            "TOP_SECRET": 4,
        }

        user_level = clearance_levels.get(user_clearance, 1)
        resource_level = clearance_levels.get(resource_class, 1)

        # Check clearance
        if user_level < resource_level:
            return {
                "result": False,
                "reason": f"Insufficient clearance: {user_clearance} cannot access {resource_class}",
            }

        # Check department (unless PUBLIC)
        if resource_class != "PUBLIC" and resource_dept:
            if user_dept != resource_dept:
                return {
                    "result": False,
                    "reason": f"Department mismatch: {user_dept} cannot access {resource_dept} resources",
                }

        # TOP_SECRET time restriction (8 AM - 4 PM)
        if resource_class == "TOP_SECRET":
            if current_hour < 8 or current_hour >= 16:
                return {
                    "result": False,
                    "reason": f"TOP_SECRET documents only accessible during business hours (8 AM - 4 PM). Current hour: {current_hour}",
                }

        return {
            "result": True,
            "reason": "Access granted by policy",
            "decision": {
                "clearance_check": "passed",
                "department_check": "passed",
                "time_check": "passed",
            },
        }

    def log_message(self, format, *args):
        """Silence default logging"""
        pass


def run_opa_server():
    """Run OPA policy server with SSL - FIXED"""
    host = "localhost"
    port = 8181

    # ============ SSL CONTEXT ============
    try:
        # Certificate paths
        ca_cert = "certs/ca.crt"
        server_cert = "certs/server.crt"
        server_key = "certs/server.key"

        # Verify certs exist
        for path in [ca_cert, server_cert, server_key]:
            if not os.path.exists(path):
                print(f"❌ Certificate not found: {path}")
                print("   Run: python create_certificates.py")
                return

        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(server_cert, server_key)
        context.load_verify_locations(cafile=ca_cert)

        # CRITICAL: For server-side, check_hostname must be False
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        print("✅ SSL context created (TLSv1.2)")

    except Exception as e:
        print(f"❌ Failed to create SSL context: {e}")
        traceback.print_exc()
        return

    # Create and start server
    try:
        httpd = HTTPServer((host, port), OPAHandler)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        print("=" * 60)
        print(" PYTHON OPA SERVER ")
        print("=" * 60)
        print(f" Port: {port}")
        print(f" URL: https://{host}:{port}")
        print(f" Health: https://{host}:{port}/health")
        print(f" Evaluate: POST https://{host}:{port}/v1/data/zta/allow")
        print("=" * 60)
        print("Policies implemented:")
        print("   Clearance hierarchy: BASIC → CONFIDENTIAL → SECRET → TOP_SECRET")
        print("   Department matching required")
        print("   TOP_SECRET: Business hours only (8 AM - 4 PM)")
        print("=" * 60)
        print(" SSL: TLSv1.2 (Python 3.13 compatibility)")
        print("\nPress Ctrl+C to stop the server")

        httpd.serve_forever()

    except KeyboardInterrupt:
        print("\n\n🛑 OPA Server stopped")
    except Exception as e:
        print(f"❌ Server error: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    run_opa_server()
