#!/usr/bin/env bash
# Extract certificate, chain and private key from a PFX as PEM files.
#
#   ./extract_pem.sh WC_Onerheem_com_2026.pfx [output-dir]
#
# Writes:
#   certificate.pem   the leaf certificate
#   cacerts.pem       the CA / intermediate chain
#   privatekey.pem    the private key, UNENCRYPTED
#
# Same three files as the manual openssl commands, with two fixes:
#   - output is piped through openssl x509 / rsa, so the "Bag Attributes / friendlyName /
#     localKeyID / subject=" preamble is stripped and each file starts with -----BEGIN
#   - the key is written as PKCS#1 (-----BEGIN RSA PRIVATE KEY-----), which is the form
#     OCI's CLI reference shows; OpenSSL 3 otherwise emits PKCS#8
#
# privatekey.pem is unencrypted. Keep the directory private and delete it when done.
set -euo pipefail
umask 077

IN=${1:?usage: $0 <file.pfx> [output-dir]}
OUTDIR=${2:-.}

[[ -f $IN ]] || { echo "ERROR: $IN not found" >&2; exit 1; }
mkdir -p "$OUTDIR"

CERT="$OUTDIR/certificate.pem"
CHAIN="$OUTDIR/cacerts.pem"
KEY="$OUTDIR/privatekey.pem"

for f in "$CERT" "$CHAIN" "$KEY"; do
  [[ -e $f ]] && { echo "ERROR: $f already exists" >&2; exit 1; }
done

SSL_MAJOR=$(openssl version | awk '{print $2}' | cut -d. -f1)

# Prompt for the password so it never lands in shell history or ps output.
if ! { exec 3< /dev/tty; } 2>/dev/null; then exec 3<&0; fi
printf 'PFX password (Enter if none): ' >&2
IFS= read -r -s PW <&3; echo >&2
export PW
trap 'unset PW' EXIT

# OpenSSL 3 needs -legacy for RC2-encrypted PFX files; OpenSSL 1.x has no such flag.
LEGACY=()
if ! openssl pkcs12 -in "$IN" -nokeys -passin env:PW -out /dev/null 2>/dev/null; then
  if [[ $SSL_MAJOR -ge 3 ]] &&
     openssl pkcs12 -legacy -in "$IN" -nokeys -passin env:PW -out /dev/null 2>/dev/null; then
    LEGACY=(-legacy)
    echo "NOTE: source PFX uses legacy encryption (RC2) - reading with -legacy"
  else
    echo "ERROR: cannot open $IN - wrong password, damaged file, or OpenSSL too old" >&2
    exit 1
  fi
fi

# 1. Certificate
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:PW -clcerts -nokeys \
  | openssl x509 -out "$CERT"

# 2. Certificate chain - cleaned one certificate at a time, order preserved
TMP=$(mktemp -d); trap 'rm -rf "$TMP"; unset PW' EXIT
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:PW -cacerts -nokeys \
  -out "$TMP/chain.raw" 2>/dev/null || : > "$TMP/chain.raw"

CHAIN_COUNT=0
: > "$CHAIN"
if grep -q "BEGIN CERTIFICATE" "$TMP/chain.raw"; then
  awk -v d="$TMP" '/BEGIN CERTIFICATE/{n++; f=d "/ca" n ".pem"} n{print > f}' "$TMP/chain.raw"
  for c in "$TMP"/ca*.pem; do
    openssl x509 -in "$c" >> "$CHAIN" && CHAIN_COUNT=$((CHAIN_COUNT + 1))
  done
fi

# 3. Private key - PKCS#1. OpenSSL 3 needs -traditional for that; 1.x is PKCS#1 already
#    and has no such flag.
TRAD=()
[[ $SSL_MAJOR -ge 3 ]] && TRAD=(-traditional)
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:PW -nocerts -nodes \
  -out "$TMP/key.raw"
openssl rsa ${TRAD[@]+"${TRAD[@]}"} -in "$TMP/key.raw" -out "$KEY" 2>/dev/null \
  || openssl ec -in "$TMP/key.raw" -out "$KEY" 2>/dev/null \
  || openssl pkey -in "$TMP/key.raw" -out "$KEY"

chmod 644 "$CERT"
[[ $CHAIN_COUNT -gt 0 ]] && chmod 644 "$CHAIN" || rm -f "$CHAIN"
chmod 600 "$KEY"

# Confirm the key actually belongs to the certificate before anyone deploys it.
CERT_HASH=$(openssl x509 -in "$CERT" -noout -pubkey | openssl sha256 | awk '{print $NF}')
KEY_HASH=$(openssl pkey -in "$KEY" -pubout | openssl sha256 | awk '{print $NF}')
[[ $CERT_HASH == "$KEY_HASH" ]] || { echo "ERROR: private key does not match certificate" >&2; exit 1; }

echo
openssl x509 -in "$CERT" -noout -subject -issuer -dates
echo "Key format : $(head -1 "$KEY")"
echo "Chain certs: $CHAIN_COUNT"
echo "Key matches certificate: YES"
[[ $CHAIN_COUNT -gt 0 ]] || echo "WARNING: no CA chain in the PFX - Java clients will fail path validation"
echo
ls -l "$CERT" ${CHAIN_COUNT:+"$CHAIN"} "$KEY" 2>/dev/null || ls -l "$CERT" "$KEY"
echo
echo "privatekey.pem is UNENCRYPTED - delete these files once loaded:"
echo "  shred -u $KEY"
