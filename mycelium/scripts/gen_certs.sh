#!/usr/bin/env bash
# gen_certs.sh – Generate self-signed TLS certs for the Rhizome NATS broker
set -e

CERT_DIR="$(dirname "$0")/../rhizome/certs"
mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

echo "[*] Generating Mycelium CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=MyceliumCA/O=ProjectMycelium" -out ca.crt

echo "[*] Generating NATS server certificate..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key \
  -subj "/CN=nats/O=ProjectMycelium" \
  -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -sha256 \
  -extfile <(echo "subjectAltName=DNS:nats,DNS:localhost,IP:127.0.0.1,IP:172.30.0.2")

echo "[*] Generating client certificate (for Spores)..."
openssl genrsa -out client.key 2048
openssl req -new -key client.key \
  -subj "/CN=mycelium-spore/O=ProjectMycelium" \
  -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365 -sha256

# Clean up CSRs
rm -f *.csr *.srl

echo "[✓] Certificates written to $CERT_DIR"
ls -la "$CERT_DIR"
