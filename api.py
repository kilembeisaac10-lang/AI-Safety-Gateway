import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import hmac

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

print("DEBUG AUTH")
print("USERNAME présent :", bool(OPERATOR_USERNAME))
print("USERNAME longueur :", len(OPERATOR_USERNAME))
print("PASSWORD présent :", bool(OPERATOR_PASSWORD))
print("PASSWORD longueur :", len(OPERATOR_PASSWORD))


class GatewayHandler(BaseHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def read_json_body(self):
        content_length = int(
            self.headers.get("Content-Length", "0")
        )

        if content_length <= 0:
            raise ValueError("Request body is required")

        if content_length > 64 * 1024:
            raise ValueError("Request body is too large")

        body = self.rfile.read(content_length)

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

        if self.path == "/debug-auth":
            self.send_json(
                200,
                {
                    "username_present": bool(OPERATOR_USERNAME),
                    "username_length": len(OPERATOR_USERNAME),
                    "password_present": bool(OPERATOR_PASSWORD),
                    "password_length": len(OPERATOR_PASSWORD)
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

        self.send_json(
            404,
            {
                "error": "Not found"
            }
        )

    def handle_session(self):

        try:
            data = self.read_json_body()

            username = data.get("username")
            password = data.get("password")

            if not isinstance(username, str):
                self.send_json(
                    400,
                    {
                        "error": "username is required"
                    }
                )
                return

            if not isinstance(password, str):
                self.send_json(
                    400,
                    {
                        "error": "password is required"
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
                        "error": "Invalid credentials"
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
                    "status": "authenticated",
                    "session_id": session_id,
                    "role": "administrator"
                }
            )

        except json.JSONDecodeError:
            self.send_json(
                400,
                {
                    "error": "Invalid JSON"
                }
            )

        except ValueError as error:
            self.send_json(
                400,
                {
                    "error": str(error)
                }
            )

        except Exception:
            self.send_json(
                500,
                {
                    "error": "Internal server error"
                }
            )

    def handle_evaluate(self):

        try:
            data = self.read_json_body()

            session_id = data.get("session_id")
            tool = data.get("tool")
            operation = data.get("operation")
            args = data.get("args", {})

            if not isinstance(session_id, str):
                self.send_json(
                    400,
                    {
                        "error": "session_id is required"
                    }
                )
                return

            if not isinstance(tool, str):
                self.send_json(
                    400,
                    {
                        "error": "tool is required"
                    }
                )
                return

            if not isinstance(operation, str):
                self.send_json(
                    400,
                    {
                        "error": "operation is required"
                    }
                )
                return

            if not isinstance(args, dict):
                self.send_json(
                    400,
                    {
                        "error": "args must be an object"
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
                    "error": "Invalid JSON"
                }
            )

        except ValueError as error:
            self.send_json(
                400,
                {
                    "error": str(error)
                }
            )

        except Exception as error:
            print(
                "Erreur /evaluate :",
                type(error).__name__
            )

            self.send_json(
                500,
                {
                    "error": "Internal server error"
                }
            )


if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", "8081")
    )

    server = HTTPServer(
        ("0.0.0.0", port),
        GatewayHandler
    )

    print("AI Safety Gateway API démarrée")
    print(f"Port : {port}")

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        print("API arrêtée")
        server.server_close()
