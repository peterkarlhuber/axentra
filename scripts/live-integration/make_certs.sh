#!/usr/bin/env bash
# Throwaway CA + server certificate (CN/SAN localhost, 127.0.0.1) for the Mailpit TLS checks.
# Usage: make_certs.sh <dir>. Valid 3 days; regenerate freely. Never use outside local tests.
set -euo pipefail
dir="${1:?usage: make_certs.sh <dir>}"
mkdir -p "$dir" && cd "$dir"
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 3 -subj "/CN=lc synthetic test CA" \
  -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:false\nextendedKeyUsage=serverAuth\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 3 -extfile ext.cnf 2>/dev/null
chmod 644 server.key  # readable by the Mailpit container user
openssl verify -CAfile ca.pem server.pem
