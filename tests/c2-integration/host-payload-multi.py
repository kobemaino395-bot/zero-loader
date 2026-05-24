#!/usr/bin/env python3
"""HTTPS server serving any file under --dir as /<name>.dat."""
import argparse, ssl, sys, subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def make_cert(certdir: Path):
    certdir.mkdir(parents=True, exist_ok=True)
    crt, key = certdir / "host.crt", certdir / "host.key"
    if not crt.exists() or not key.exists():
        subprocess.check_call(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                               "-keyout", str(key), "-out", str(crt),
                               "-days", "365", "-subj", "/CN=zero-loader-test"])
    return crt, key


def make_handler(serve_dir: Path):
    class H(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            sys.stderr.write(f"[srv {self.client_address[0]}] {fmt % args}\n"); sys.stderr.flush()

        def do_GET(self):
            name = self.path.lstrip("/").split("?")[0]
            f = serve_dir / name
            if not f.is_file() or ".." in name:
                self.send_response(404); self.end_headers(); return
            data = f.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers(); self.wfile.write(data)
    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18443)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--certdir", default="certs")
    args = ap.parse_args()
    serve = Path(args.dir).resolve()
    crt, key = make_cert(Path(args.certdir).resolve())
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(str(crt), str(key))
    srv = HTTPServer(("0.0.0.0", args.port), make_handler(serve))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    files = sorted(p.name for p in serve.iterdir() if p.is_file())
    print(f"[+] Serving {len(files)} files from {serve} on https://0.0.0.0:{args.port}/", flush=True)
    for f in files: print(f"    /{f}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
