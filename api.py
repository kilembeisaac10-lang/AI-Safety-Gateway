import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import json

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from gateway import SafetyGateway

gateway = SafetyGateway()


class GatewayHandler(BaseHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

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

        if self.path != "/evaluate":
            self.send_json(
                404,
                {
                    "error": "Not found"
                }
            )
            return

        try:
            content_length = int(
                self.headers.get("Content-Length", "0")
            )

            if content_length <= 0:
                self.send_json(
                    400,
                    {
                        "error": "Request body is required"
                    }
                )
                return

            body = self.rfile.read(content_length)

            data = json.loads(
                body.decode("utf-8")
            )

            if not isinstance(data, dict):
                self.send_json(
                    400,
                    {
                        "error": "JSON body must be an object"
                    }
                )
                return

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
