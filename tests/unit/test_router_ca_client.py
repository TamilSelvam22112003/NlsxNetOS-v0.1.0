import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric import rsa

from nlsxnetos.nls.rsa import public_key_b64 as rsa_public_key_b64
from nlsxnetos.router_ca.client import RouterCAClient


class Handler(BaseHTTPRequestHandler):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ed25519_public = base64.b64encode(b"A" * 32).decode()
    record = {
        "id": 1,
        "prefix": "10.1.0.0/24",
        "label": "router-a",
        "endpoint": "192.0.2.1:4789",
        "public_key": ed25519_public,
        "encryption_public_key": rsa_public_key_b64(rsa_key),
        "certificate": "test-cert",
        "timestamp": 1791370000,
    }

    def log_message(self, *_args):
        return

    def do_GET(self):
        if self.path.startswith("/v1/health"):
            body = {"status": "ok"}
        elif self.path.startswith("/v1/routers/resolve-identity"):
            body = {"router": self.record}
        elif self.path.startswith("/v1/routers/resolve"):
            body = {"router": self.record}
        elif self.path.startswith("/v1/routers/1"):
            body = {"router": self.record}
        else:
            self.send_response(404)
            self.end_headers()
            return
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def test_router_ca_identity_resolution():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = RouterCAClient(f"http://127.0.0.1:{server.server_port}")
        entry = client.resolve_identity(Handler.ed25519_public)
        assert entry.id == 1
        assert entry.public_key == Handler.ed25519_public
        assert entry.encryption_public_key == Handler.record["encryption_public_key"]
        assert entry.endpoint == "192.0.2.1:4789"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
