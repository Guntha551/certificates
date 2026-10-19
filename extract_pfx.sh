#!/usr/bin/env bash
# Extract clean PEM components from a PFX for SSL enablement and OCI Load Balancer upload.
#
#   ./extract_pfx.sh <file.pfx> [output-dir]
#
# Produces, in the output directory:
#   certificate.pem        leaf certificate, clean PEM        (OCI: --public-certificate-file)
#   cacerts.pem            CA chain, clean PEM                (OCI: --ca-certificate-file)
#   privatekey.pem         private key, unencrypted PKCS#1    (OCI: --private-key-file)
#   privatekey_pkcs8.pem   same key in PKCS#8, for Java/other consumers
#   fullchain.pem          leaf + chain concatenated          (nginx/Apache style)
#   certificate.cer        leaf in DER, for tools wanting .cer
#
# Why not just `openssl pkcs12 -nokeys -out cert.pem`:
#   that output carries a "Bag Attributes / localKeyID / friendlyName / subject= / issuer="
#   preamble before the PEM block. Some consumers reject it. Everything here is piped through
#   openssl x509/rsa so only the PEM block itself is written.
#
# OCI's CLI reference shows the private key as "-----BEGIN RSA PRIVATE KEY-----" (PKCS#1),
# while OpenSSL 3 emits PKCS#8 ("-----BEGIN PRIVATE KEY-----") from pkcs12. privatekey.pem
# is therefore converted to PKCS#1 for the OCI upload; the PKCS#8 copy is kept alongside.
#
# The private key is written UNENCRYPTED. Keep the output directory private and remove it
# once the key has been uploaded.
set -euo pipefail
umask 077

IN=${1:?usage: $0 <file.pfx> [output-dir]}
OUTDIR=${2:-./pem_$(date +%Y%m%d_%H%M%S)}

[[ -f $IN ]] || { echo "ERROR: $IN not found" >&2; exit 1; }
command -v openssl >/dev/null || { echo "ERROR: openssl not found" >&2; exit 1; }

if [[ -e $OUTDIR ]]; then
  echo "ERROR: $OUTDIR already exists - choose another directory" >&2
  exit 1
fi

SSL_VER=$(openssl version | awk '{print $2}')
SSL_MAJOR=${SSL_VER%%.*}

mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

WORK=$(mktemp -d)
cleanup() {
  if [[ -d $WORK ]]; then
    find "$WORK" -type f -exec shred -u {} + 2>/dev/null || rm -rf "$WORK"/* 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
  fi
  unset SRC_PW 2>/dev/null || true
}
trap cleanup EXIT

if ! { exec 3< /dev/tty; } 2>/dev/null; then exec 3<&0; fi
printf 'PFX password (Enter if none): ' >&2
IFS= read -r -s SRC_PW <&3 || { echo >&2; echo "ERROR: no password supplied" >&2; exit 1; }
echo >&2
export SRC_PW

# OpenSSL 3 needs -legacy for RC2-encrypted PFX files; 1.x has no such flag.
LEGACY=()
if ! openssl pkcs12 -in "$IN" -nokeys -passin env:SRC_PW -out /dev/null 2>/dev/null; then
  if [[ $SSL_MAJOR -ge 3 ]] &&
     openssl pkcs12 -legacy -in "$IN" -nokeys -passin env:SRC_PW -out /dev/null 2>/dev/null; then
    LEGACY=(-legacy)
    echo "NOTE: source uses legacy encryption (RC2) - reading with -legacy"
  else
    echo "ERROR: cannot open $IN" >&2
    echo "       Wrong password, damaged file, or OpenSSL $SSL_VER too old for its encryption." >&2
    exit 1
  fi
fi

echo "== 1. Extract"
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:SRC_PW \
  -clcerts -nokeys -out "$WORK/leaf.raw"
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:SRC_PW \
  -nocerts -nodes  -out "$WORK/key.raw"
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:SRC_PW \
  -cacerts -nokeys -out "$WORK/chain.raw" 2>/dev/null || : > "$WORK/chain.raw"

grep -q "BEGIN CERTIFICATE" "$WORK/leaf.raw" || { echo "ERROR: no certificate in $IN" >&2; exit 1; }
grep -q "PRIVATE KEY"      "$WORK/key.raw"  || { echo "ERROR: no private key in $IN" >&2; exit 1; }

LEAF_COUNT=$(grep -c "BEGIN CERTIFICATE" "$WORK/leaf.raw" || true)
KEY_COUNT=$(grep -c "BEGIN.*PRIVATE KEY" "$WORK/key.raw" || true)
if [[ $LEAF_COUNT -gt 1 || $KEY_COUNT -gt 1 ]]; then
  echo "ERROR: $LEAF_COUNT leaf certificate(s) and $KEY_COUNT key(s) found." >&2
  echo "       This script handles a single key pair only." >&2
  exit 1
fi

echo "== 2. Write clean PEM (bag attributes stripped)"

# Leaf: re-emit through x509 so only the PEM block lands in the file.
openssl x509 -in "$WORK/leaf.raw" -out "$OUTDIR/certificate.pem"
openssl x509 -in "$OUTDIR/certificate.pem" -outform DER -out "$OUTDIR/certificate.cer"

# Private key: PKCS#8 copy, then PKCS#1 for OCI.
KEY_ALGO=$(openssl pkey -in "$WORK/key.raw" -noout -text 2>/dev/null | head -1)
openssl pkey -in "$WORK/key.raw" -out "$OUTDIR/privatekey_pkcs8.pem"

# OpenSSL 3's `rsa` subcommand writes PKCS#8 by default and needs -traditional for PKCS#1.
# OpenSSL 1.x writes PKCS#1 by default and has no -traditional flag.
TRAD=()
[[ $SSL_MAJOR -ge 3 ]] && TRAD=(-traditional)

if openssl rsa ${TRAD[@]+"${TRAD[@]}"} -in "$WORK/key.raw" \
     -out "$OUTDIR/privatekey.pem" 2>/dev/null; then
  :
elif openssl ec -in "$WORK/key.raw" -out "$OUTDIR/privatekey.pem" 2>/dev/null; then
  :
else
  cp "$OUTDIR/privatekey_pkcs8.pem" "$OUTDIR/privatekey.pem"
fi

KEY_FORM=$(head -1 "$OUTDIR/privatekey.pem")
case $KEY_FORM in
  *"BEGIN RSA PRIVATE KEY"*) KEY_FORM="PKCS#1 (BEGIN RSA PRIVATE KEY) - matches OCI's documented example" ;;
  *"BEGIN EC PRIVATE KEY"*)  KEY_FORM="SEC1 EC (BEGIN EC PRIVATE KEY)" ;;
  *"BEGIN PRIVATE KEY"*)     KEY_FORM="PKCS#8 (BEGIN PRIVATE KEY) - conversion to PKCS#1 did not apply" ;;
  *)                         KEY_FORM="unrecognised: $KEY_FORM" ;;
esac

# Chain: split, clean each, concatenate in the order found.
CHAIN_COUNT=0
: > "$OUTDIR/cacerts.pem"
if grep -q "BEGIN CERTIFICATE" "$WORK/chain.raw" 2>/dev/null; then
  awk -v dir="$WORK" '
    /BEGIN CERTIFICATE/ { n++; out = dir "/ca" n ".pem" }
    n { print > out }
  ' "$WORK/chain.raw"
  for c in "$WORK"/ca*.pem; do
    [[ -f $c ]] || continue
    openssl x509 -in "$c" >> "$OUTDIR/cacerts.pem" 2>/dev/null && CHAIN_COUNT=$((CHAIN_COUNT + 1))
  done
fi
[[ $CHAIN_COUNT -gt 0 ]] || rm -f "$OUTDIR/cacerts.pem"

cat "$OUTDIR/certificate.pem" > "$OUTDIR/fullchain.pem"
[[ $CHAIN_COUNT -gt 0 ]] && cat "$OUTDIR/cacerts.pem" >> "$OUTDIR/fullchain.pem"

chmod 600 "$OUTDIR"/*

echo "== 3. Verify"
openssl x509 -in "$OUTDIR/certificate.pem" -noout -subject -issuer -dates
SAN=$(openssl x509 -in "$OUTDIR/certificate.pem" -noout -text 2>/dev/null \
      | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//') || true
echo "SAN: ${SAN:-(none)}"
echo "Key type: ${KEY_ALGO:-unknown}"
echo "Key format written to privatekey.pem: $KEY_FORM"
echo "CA certificates in cacerts.pem: $CHAIN_COUNT"

CERT_HASH=$(openssl x509 -in "$OUTDIR/certificate.pem" -noout -pubkey | openssl sha256 | awk '{print $NF}')
KEY_HASH=$(openssl pkey -in "$OUTDIR/privatekey.pem" -pubout | openssl sha256 | awk '{print $NF}')
[[ $CERT_HASH == "$KEY_HASH" ]] || { echo "ERROR: private key does not match certificate" >&2; exit 1; }
echo "Private key matches certificate: YES"

# No bag attributes, no stray text before the PEM header.
for f in "$OUTDIR/certificate.pem" "$OUTDIR/privatekey.pem" "$OUTDIR/privatekey_pkcs8.pem"; do
  if head -1 "$f" | grep -qv -- "-----BEGIN"; then
    echo "ERROR: $f does not start with a PEM header" >&2; exit 1
  fi
done
if [[ $CHAIN_COUNT -gt 0 ]] && head -1 "$OUTDIR/cacerts.pem" | grep -qv -- "-----BEGIN"; then
  echo "ERROR: cacerts.pem does not start with a PEM header" >&2; exit 1
fi
echo "All PEM files start with a PEM header: YES"

if [[ $CHAIN_COUNT -eq 0 ]]; then
  echo "WARNING: no CA chain in the PFX. Java clients will fail path validation."
  echo "         Ask for the intermediate certificate before uploading to the load balancer."
else
  if openssl verify -untrusted "$OUTDIR/cacerts.pem" "$OUTDIR/certificate.pem" >/dev/null 2>&1; then
    echo "Chain verifies against system trust store: YES"
  else
    echo "NOTE: chain does not verify against the system trust store."
    echo "      Expected for an internal CA; investigate for a public certificate."
  fi
fi

NOT_AFTER=$(openssl x509 -in "$OUTDIR/certificate.pem" -noout -enddate | sed 's/notAfter=//')
if ! openssl x509 -in "$OUTDIR/certificate.pem" -noout -checkend 0 >/dev/null 2>&1; then
  echo "WARNING: certificate has ALREADY EXPIRED ($NOT_AFTER)"
elif ! openssl x509 -in "$OUTDIR/certificate.pem" -noout -checkend 2592000 >/dev/null 2>&1; then
  echo "WARNING: certificate expires within 30 days ($NOT_AFTER)"
fi

echo
echo "DONE: $OUTDIR"
ls -l "$OUTDIR"
echo
echo "For the OCI load balancer:"
echo "  --public-certificate-file $OUTDIR/certificate.pem"
echo "  --private-key-file        $OUTDIR/privatekey.pem"
[[ $CHAIN_COUNT -gt 0 ]] && echo "  --ca-certificate-file     $OUTDIR/cacerts.pem"
echo
echo "The private key in $OUTDIR is UNENCRYPTED. Remove the directory once uploaded:"
echo "  find $OUTDIR -type f -exec shred -u {} + && rmdir $OUTDIR"
