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

        self.send_header(
            "Content-Type",
            "application/json"
        )

        self.send_header(
            "Content-Length",
            str(len(body))
        )

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


if __name__ == "__main__":

    server = HTTPServer(
        ("0.0.0.0", 8081),
        GatewayHandler
    )

    print("AI Safety Gateway API démarrée")
    print("http://127.0.0.1:8081/health")

    try:
        server.serve_forever()

    except KeyboardInterrupt:

        print("API arrêtée")

        server.server_close()