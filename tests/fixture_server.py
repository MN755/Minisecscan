"""Loopback-only HTTPS fixtures for exercising the real scanner transport."""

import argparse
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests


SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
PAGES = {
    "/secure": "<h1>Secure fixture</h1>",
    "/insecure": "<h1>Missing security headers</h1>",
    "/mixed-content": '<img src="http://insecure.invalid/image.png">',
    "/password-get": '<form method="get"><input type="password"></form>',
    "/password-http": '<form method="post" action="http://insecure.invalid/login">'
    '<input type="password"><input name="csrf_token"></form>',
    "/cookie": "<h1>Insecure cookie</h1>",
    "/csrf": '<form method="post"><input name="message"></form>',
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in PAGES:
            self.send_error(404)
            return
        body = PAGES[self.path].encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if self.path != "/insecure":
            for name, value in SECURE_HEADERS.items():
                self.send_header(name, value)
        if self.path == "/cookie":
            self.send_header("Set-Cookie", "session=fixture; SameSite=None")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FixtureServer:
    def __init__(self, directory=None):
        self.temporary = tempfile.TemporaryDirectory(prefix="minisecscan-")
        self.directory = Path(directory or self.temporary.name)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        certificate = self.directory / "localhost.crt"
        key = self.directory / "localhost.key"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-days", "1", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
             "-keyout", str(key), "-out", str(certificate)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        key.chmod(0o600)
        # Append the fixture certificate; retain the inherited CA trust.
        inherited = (os.environ.get("REQUESTS_CA_BUNDLE")
                     or os.environ.get("CURL_CA_BUNDLE") or requests.certs.where())
        self.base_bundle = inherited
        self.ca_bundle = self.directory / "ca-bundle.crt"
        self.ca_bundle.write_bytes(Path(inherited).read_bytes() + b"\n" + certificate.read_bytes())
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.url = f"https://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.temporary.cleanup()

    def environment(self, trusted=True):
        env = dict(os.environ)
        env["REQUESTS_CA_BUNDLE"] = str(self.ca_bundle if trusted else self.base_bundle)
        # Only the loopback fixture is exempted; preserve inherited proxy configuration.
        env["NO_PROXY"] = ",".join(filter(None, [env.get("NO_PROXY"), "127.0.0.1", "localhost"]))
        return env


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    def stop(*_):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    with FixtureServer(args.directory) as fixture:
        state = {"url": fixture.url, "ca_bundle": str(fixture.ca_bundle)}
        pending = fixture.directory / "fixture.json.tmp"
        pending.write_text(json.dumps(state))
        pending.replace(fixture.directory / "fixture.json")
        threading.Event().wait()


if __name__ == "__main__":
    main()
