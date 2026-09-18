import os
import sys

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

if PROJECT_DIR not in sys.path:
    sys.path.insert(0, PROJECT_DIR)

from api import GatewayHandler
from http.server import HTTPServer

PORT = int(os.environ.get("PORT", "8081"))

server = HTTPServer(
    ("0.0.0.0", PORT),
    GatewayHandler
)

print("AI Safety Gateway démarré")
print(f"Port : {PORT}")

try:
    server.serve_forever()
except KeyboardInterrupt:
    print("Arrêt du serveur")
    server.server_close()