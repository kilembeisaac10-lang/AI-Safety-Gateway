import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import hmac
import threading

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from gateway import SafetyGateway

gateway = SafetyGateway()

OPERATOR_USERNAME = os.environ.get("AI_OPERATOR_USERNAME")
OPERATOR_PASSWORD = os.environ.get("AI_OPERATOR_PASSWORD")

if not OPERATOR_USERNAME or not OPERATOR_PASSWORD:
    raise RuntimeError(
        "Les identifiants opérateur doivent être configurés."
    )


# --------------------------------------------------
# RATE LIMITING
# --------------------------------------------------

LOGIN_WINDOW = 60
LOGIN_MAX_ATTEMPTS = 5
LOGIN_BLOCK_TIME = 300

_login_lock = threading.Lock()
_login_attempts = {}


def get_client_key(handler):

    forwarded_for = handler.headers.get(
        "X-Forwarded-For"
    )

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return handler.client_address[0]


def check_login_rate_limit(client_key):

    now = time.time()

    with _login_lock:

        record = _login_attempts.get(
            client_key
        )

        if record is None:
            record = {
                "attempts": [],
                "blocked_until": 0
            }

            _login_attempts[
                client_key
            ] = record

        if now < record["blocked_until"]:
            return False

        record["attempts"] = [
            timestamp
            for timestamp in record["attempts"]
            if now - timestamp < LOGIN_WINDOW
        ]

        if len(record["attempts"]) >= LOGIN_MAX_ATTEMPTS:

            record["blocked_until"] = (
                now + LOGIN_BLOCK_TIME
            )

            record["attempts"] = []

            return False

        record["attempts"].append(now)

        return True


# --------------------------------------------------
# HTTP HANDLER
# --------------------------------------------------

class GatewayHandler(BaseHTTPRequestHandler):

    def send_json(self, status, data):

        body = json.dumps(
            data
        ).encode("utf-8")

        self.send_response(status)

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

        self.send_header(
            "X-Content-Type-Options",
            "nosniff"
        )

        self.send_header(
            "Cache-Control",
            "no-store"
        )

        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'"
        )

        self.end_headers()

        self.wfile.write(body)

    def read_json_body(self):

        content_length = int(
            self.headers.get(
                "Content-Length",
                "0"
            )
        )

        if content_length <= 0:
            raise ValueError(
                "Request body is required"
            )

        if content_length > 64 * 1024:
            raise ValueError(
                "Request body is too large"
            )

        body = self.rfile.read(
            content_length
        )

        data = json.loads(
            body.decode("utf-8")
        )

        if not isinstance(data, dict):
            raise ValueError(
                "JSON body must be an object"
            )

        return data

    def do_GET(self):

        if self.path == "/health":

            self.send_json(
                200,
                {
                    "status": "online",
                    "gateway": "AI Safety Gateway"
                }
            )

            return

        self.send_json(
            404,
            {
                "error": "Not found"
            }
        )

    def do_POST(self):

        if self.path == "/session":

            self.handle_session()

            return

        if self.path == "/evaluate":

            self.handle_evaluate()

            return

        if self.path == "/emergency-stop":

            self.handle_emergency_stop()

            return

        self.send_json(
            404,
            {
                "error": "Not found"
            }
        )

    def handle_session(self):

        client_key = get_client_key(
            self
        )

        if not check_login_rate_limit(
            client_key
        ):

            self.send_json(
                429,
                {
                    "error": "Too many login attempts"
                }
            )

            return

        try:

            data = self.read_json_body()

            username = data.get(
                "username"
            )

            password = data.get(
                "password"
            )

            if not isinstance(
                username,
                str
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "username is required"
                    }
                )

                return

            if not isinstance(
                password,
                str
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "password is required"
                    }
                )

                return

            username_ok = hmac.compare_digest(
                username,
                OPERATOR_USERNAME
            )

            password_ok = hmac.compare_digest(
                password,
                OPERATOR_PASSWORD
            )

            if not username_ok or not password_ok:

                self.send_json(
                    401,
                    {
                        "error":
                        "Invalid credentials"
                    }
                )

                return

            session_id = gateway.create_session(
                username,
                "administrator"
            )

            self.send_json(
                200,
                {
                    "status":
                    "authenticated",

                    "session_id":
                    session_id,

                    "role":
                    "administrator"
                }
            )

        except json.JSONDecodeError:

            self.send_json(
                400,
                {
                    "error":
                    "Invalid JSON"
                }
            )

        except ValueError as error:

            self.send_json(
                400,
                {
                    "error":
                    str(error)
                }
            )

        except Exception:

            self.send_json(
                500,
                {
                    "error":
                    "Internal server error"
                }
            )

    def handle_evaluate(self):

        try:

            data = self.read_json_body()

            session_id = data.get(
                "session_id"
            )

            tool = data.get(
                "tool"
            )

            operation = data.get(
                "operation"
            )

            args = data.get(
                "args",
                {}
            )

            if not isinstance(
                session_id,
                str
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "session_id is required"
                    }
                )

                return

            if not isinstance(
                tool,
                str
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "tool is required"
                    }
                )

                return

            if not isinstance(
                operation,
                str
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "operation is required"
                    }
                )

                return

            if not isinstance(
                args,
                dict
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "args must be an object"
                    }
                )

                return

            result = gateway.evaluate(
                session_id,
                tool,
                operation,
                args
            )

            self.send_json(
                200,
                result
            )

        except json.JSONDecodeError:

            self.send_json(
                400,
                {
                    "error":
                    "Invalid JSON"
                }
            )

        except ValueError as error:

            self.send_json(
                400,
                {
                    "error":
                    str(error)
                }
            )

        except Exception:

            self.send_json(
                500,
                {
                    "error":
                    "Internal server error"
                }
            )

    def handle_emergency_stop(self):

        try:

            data = self.read_json_body()

            session_id = data.get(
                "session_id"
            )

            enabled = data.get(
                "enabled"
            )

            if not isinstance(
                session_id,
                str
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "session_id is required"
                    }
                )

                return

            if not isinstance(
                enabled,
                bool
            ):

                self.send_json(
                    400,
                    {
                        "error":
                        "enabled must be a boolean"
                    }
                )

                return

            if not gateway.auth.validate_session(
                session_id
            ):

                self.send_json(
                    401,
                    {
                        "error":
                        "Invalid or expired session"
                    }
                )

                return

            if not gateway.auth.has_permission(
                session_id,
                "manage"
            ):

                self.send_json(
                    403,
                    {
                        "error":
                        "Administrator permission required"
                    }
                )

                return

            gateway.stop.set_stop(
                enabled
            )

            self.send_json(
                200,
                {
                    "status":
                    "updated",

                    "emergency_stop":
                    enabled
                }
            )

        except json.JSONDecodeError:

            self.send_json(
                400,
                {
                    "error":
                    "Invalid JSON"
                }
            )

        except ValueError as error:

            self.send_json(
                400,
                {
                    "error":
                    str(error)
                }
            )

        except Exception:

            self.send_json(
                500,
                {
                    "error":
                    "Internal server error"
                }
            )


if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            "8081"
        )
    )

    server = HTTPServer(
        ("0.0.0.0", port),
        GatewayHandler
    )

    print(
        "AI Safety Gateway API démarrée",
        flush=True
    )

    print(
        f"Port : {port}",
        flush=True
    )

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print(
            "API arrêtée",
            flush=True
        )

        server.server_close()
