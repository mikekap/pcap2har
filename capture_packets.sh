#!/usr/bin/env bash
set -mEeo pipefail

KEYLOG="$(mktemp /tmp/sslkeys.XXXXXX)"
PROFILE="$(mktemp -d /tmp/chrome-prof.XXXXXX)"
PCAP="$(mktemp /tmp/capture.XXXXXX)"
OUT="$PWD/capture.pcapng"

cleanup() {
  # best-effort cleanup
  sudo rm -f "$PCAP" 2>/dev/null || true
  rm -f "$KEYLOG" 2>/dev/null || true
  rm -rf "$PROFILE" 2>/dev/null || true
}
trap cleanup EXIT

# Start tcpdump as root; grab the *tcpdump* child PID
sudo tcpdump -U -s 0 -i any -w "$PCAP" -Z "$USER" \
  '(tcp port 80 or tcp port 443 or udp port 443)' &
sleep 1
SUDO_PID=$!
# Find the actual tcpdump PID (child of sudo)
TCPDUMP_PID="$(pgrep -P "$SUDO_PID" tcpdump || true)"
echo "tcpdump running with pid $TCPDUMP_PID"

# Launch Chrome with TLS key log
SSLKEYLOGFILE="$KEYLOG" \
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --user-data-dir="$PROFILE" --no-first-run "$@"

# Stop tcpdump cleanly and wait for it to flush/close the file
if [[ -n "$TCPDUMP_PID" ]]; then
  sudo kill -INT "$TCPDUMP_PID" || true
else
  sudo kill -INT "$SUDO_PID" || true
fi
wait "$SUDO_PID" || true

# Convert + inject TLS secrets into pcapng
editcap --inject-secrets "tls,$KEYLOG" "$PCAP" "$OUT"

echo "Decrypted capture written to: $OUT"
