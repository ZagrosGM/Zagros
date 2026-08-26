#!/bin/sh
set -eu
umask 077
DATA=${ZAGROS_NODE_DATA:-/var/lib/zagros-node}
CERT=${ZAGROS_NODE_TLS_CERT:-$DATA/tls/node.crt}
KEY=${ZAGROS_NODE_TLS_KEY:-$DATA/tls/node.key}
mkdir -p "$DATA" "$(dirname "$CERT")" /var/lib/zagros/cores
chmod 0700 "$DATA" "$(dirname "$CERT")"

# Certificates may be operator-mounted. Otherwise create a node-local identity;
# the panel pins its SHA-256 fingerprint during registration.
if [ ! -s "$CERT" ] || [ ! -s "$KEY" ]; then
  name=${ZAGROS_NODE_NAME:-zagros-node}
  address=${ZAGROS_NODE_ADDRESS:-$name}
  case "$address" in
    *:*) san="IP:$address" ;;
    *[!0-9.]*) san="DNS:$address" ;;
    *) san="IP:$address" ;;
  esac
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 825 \
    -subj "/CN=$address/O=Zagros Node" -addext "subjectAltName=$san" \
    -keyout "$KEY.tmp" -out "$CERT.tmp" >/dev/null 2>&1
  chmod 0600 "$KEY.tmp" "$CERT.tmp"
  mv "$KEY.tmp" "$KEY"; mv "$CERT.tmp" "$CERT"
fi
chmod 0600 "$KEY" "$CERT"

if [ -z "${ZAGROS_NODE_REGISTRATION_HASH:-}" ]; then
  echo "ZAGROS_NODE_REGISTRATION_HASH is required (SHA-256 of a one-time token)" >&2
  exit 64
fi
exec "$@"
