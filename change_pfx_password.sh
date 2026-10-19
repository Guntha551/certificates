#!/usr/bin/env bash
# Re-protect a PFX (PKCS#12) with a new password.
#
#   ./change_pfx_password.sh <input.pfx> [output.pfx] [alias]
#
# - Passwords are prompted for, never passed on the command line.
# - The unencrypted key only ever lives in a private temp dir that is shredded on exit.
# - Output uses 3DES/SHA1 so older Java (JRockit, JDK 6/7/early 8) and Oracle orapki can read it.
# - The source alias (friendlyName) is preserved unless one is given on the command line.
#
# Tested against bash 4.2 (OL7) and bash 4.4+/5.x (OL8/OL9), OpenSSL 1.0.2 / 1.1.1 / 3.x.
set -euo pipefail
umask 077

IN=${1:?usage: $0 <input.pfx> [output.pfx] [alias]}
OUT=${2:-${IN%.*}_new.pfx}
ALIAS=${3:-}

[[ -f $IN ]] || { echo "ERROR: $IN not found" >&2; exit 1; }
if [[ -e $OUT ]]; then
  echo "ERROR: $OUT already exists - choose another name" >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "ERROR: openssl not found" >&2; exit 1; }

# OpenSSL major version: 3 needs -legacy for RC2-encrypted PFX files, 1.x has no such flag.
SSL_VER=$(openssl version | awk '{print $2}')
SSL_MAJOR=${SSL_VER%%.*}

WORK=$(mktemp -d)
cleanup() {
  if [[ -d $WORK ]]; then
    find "$WORK" -type f -exec shred -u {} + 2>/dev/null || rm -f "$WORK"/* 2>/dev/null || true
    rmdir "$WORK" 2>/dev/null || true
  fi
  unset SRC_PW NEW_PW NEW_PW2 2>/dev/null || true
}
trap cleanup EXIT

# Read from the terminal when there is one so the prompts work even if stdin is redirected,
# but fall back to stdin so the script still runs under cron, ssh -T, Ansible or a pipe.
if ! { exec 3< /dev/tty; } 2>/dev/null; then exec 3<&0; fi
ask() { # ask <varname> <prompt>
  local __v=$1
  printf '%s' "$2" >&2
  IFS= read -r -s "$__v" <&3 || { echo >&2; echo "ERROR: no password supplied" >&2; exit 1; }
  echo >&2
}

ask SRC_PW  "Current PFX password (from Network team): "
ask NEW_PW  "New PFX password: "
ask NEW_PW2 "Re-enter new PFX password: "
[[ $NEW_PW == "$NEW_PW2" ]] || { echo "ERROR: new passwords do not match" >&2; exit 1; }
[[ -n $NEW_PW ]] || { echo "ERROR: new password is empty" >&2; exit 1; }
export SRC_PW NEW_PW

# Decide whether -legacy is needed. Empty arrays are expanded with the ${arr[@]+...} guard
# because bash 4.2 aborts on "${arr[@]}" when the array is empty and set -u is on.
LEGACY=()
if ! openssl pkcs12 -in "$IN" -nokeys -passin env:SRC_PW -out /dev/null 2>/dev/null; then
  if [[ $SSL_MAJOR -ge 3 ]] && openssl pkcs12 -legacy -in "$IN" -nokeys -passin env:SRC_PW -out /dev/null 2>/dev/null; then
    LEGACY=(-legacy)
    echo "NOTE: source PFX uses legacy encryption (RC2/40-bit) - reading with -legacy"
  else
    echo "ERROR: cannot open $IN" >&2
    echo "       Wrong password, damaged file, or OpenSSL $SSL_VER is too old for its encryption." >&2
    exit 1
  fi
fi

echo "== 1. Extract certificate, private key and CA chain"
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:SRC_PW -clcerts -nokeys -out "$WORK/cert.pem"
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:SRC_PW -nocerts -nodes  -out "$WORK/key.pem"
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:SRC_PW -cacerts -nokeys -out "$WORK/chain.pem"

grep -q "BEGIN CERTIFICATE" "$WORK/cert.pem" || { echo "ERROR: no certificate in PFX" >&2; exit 1; }
grep -q "PRIVATE KEY"      "$WORK/key.pem"  || { echo "ERROR: no private key in PFX" >&2; exit 1; }

LEAF=$(grep -c "BEGIN CERTIFICATE" "$WORK/cert.pem" || true)
KEYS=$(grep -c "BEGIN.*PRIVATE KEY" "$WORK/key.pem" || true)
CHAIN=$(grep -c "BEGIN CERTIFICATE" "$WORK/chain.pem" || true)

if [[ $LEAF -gt 1 || $KEYS -gt 1 ]]; then
  echo "ERROR: PFX holds $LEAF leaf certificate(s) and $KEYS private key(s)." >&2
  echo "       This script handles a single key pair only - split it manually." >&2
  exit 1
fi

# Preserve the source alias unless one was supplied. WebLogic and orapki both key off this.
if [[ -z $ALIAS ]]; then
  ALIAS=$(openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:SRC_PW -nokeys -clcerts 2>/dev/null \
          | awk -F': ' '/friendlyName/{print $2; exit}' | tr -d '\r') || true
fi

echo "== 2. Verify"
openssl x509 -in "$WORK/cert.pem" -noout -subject -issuer -dates
SAN=$(openssl x509 -in "$WORK/cert.pem" -noout -text 2>/dev/null \
      | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//') || true
echo "SAN: ${SAN:-(none)}"
echo "Alias: ${ALIAS:-(none - OpenSSL will assign one)}"
echo "CA certificates in chain: $CHAIN"

CERT_HASH=$(openssl x509 -in "$WORK/cert.pem" -noout -pubkey | openssl sha256 | awk '{print $NF}')
KEY_HASH=$(openssl pkey -in "$WORK/key.pem" -pubout | openssl sha256 | awk '{print $NF}')
[[ $CERT_HASH == "$KEY_HASH" ]] || { echo "ERROR: private key does not match certificate" >&2; exit 1; }
echo "Private key matches certificate: YES"
[[ $CHAIN -ge 1 ]] || echo "WARNING: PFX has no CA chain - ask the Network team for the intermediate certificate"

echo "== 3. Re-package with the new password"
NAME=()
[[ -n $ALIAS ]] && NAME=(-name "$ALIAS")
CERTFILE=()
[[ $CHAIN -ge 1 ]] && CERTFILE=(-certfile "$WORK/chain.pem")

openssl pkcs12 -export -in "$WORK/cert.pem" -inkey "$WORK/key.pem" \
  ${CERTFILE[@]+"${CERTFILE[@]}"} ${NAME[@]+"${NAME[@]}"} \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
  -passout env:NEW_PW -out "$OUT"
chmod 600 "$OUT"

echo "== 4. Validate $OUT with the NEW password"
openssl pkcs12 -in "$OUT" -passin env:NEW_PW -clcerts -nokeys 2>/dev/null \
  | openssl x509 -noout -subject -enddate

# The key must actually come back out, not just the certificates.
openssl pkcs12 -in "$OUT" -passin env:NEW_PW -nocerts -nodes 2>/dev/null | grep -q "PRIVATE KEY" \
  || { echo "ERROR: private key is not readable from $OUT with the new password" >&2; exit 1; }
echo "Private key readable with new password: YES"

NEW_CERTS=$(openssl pkcs12 -in "$OUT" -passin env:NEW_PW -nokeys 2>/dev/null | grep -c 'BEGIN CERTIFICATE' || true)
echo "Certificates in new PFX: $NEW_CERTS"
[[ $NEW_CERTS -eq $((LEAF + CHAIN)) ]] \
  || echo "WARNING: expected $((LEAF + CHAIN)) certificates, found $NEW_CERTS"

if [[ $SRC_PW != "$NEW_PW" ]]; then
  if openssl pkcs12 -in "$OUT" -passin env:SRC_PW -nokeys -out /dev/null 2>/dev/null; then
    echo "ERROR: old password still opens $OUT" >&2; exit 1
  fi
  echo "Old password rejected: YES"
fi

if command -v keytool >/dev/null; then
  echo "-- keytool view --"
  keytool -list -v -keystore "$OUT" -storetype PKCS12 -storepass:env NEW_PW 2>/dev/null \
    | grep -E "Alias name|Entry type|Certificate chain length|Owner:|Valid from" || true
fi

echo
echo "DONE: $OUT  (original $IN left unchanged)"
sha256sum "$OUT"
