#!/usr/bin/env bash
# Extract the public certificate (.cer) from a PFX.
#
#   ./extract_cer.sh WC_Onerheem_com_2026.pfx [output.cer]
#
# Writes a Base64-encoded X.509 certificate - the same thing Windows calls
# "Base64 encoded X.509 (.CER)". No private key, so the file is not sensitive.
#
# For a DER-encoded .cer instead, add -outform DER to the openssl x509 call below,
# or run:  openssl x509 -in output.cer -outform DER -out output.der
set -euo pipefail

IN=${1:?usage: $0 <file.pfx> [output.cer]}
OUT=${2:-${IN%.*}.cer}

[[ -f $IN ]] || { echo "ERROR: $IN not found" >&2; exit 1; }
[[ -e $OUT ]] && { echo "ERROR: $OUT already exists" >&2; exit 1; }

# Prompt for the password so it never lands in shell history or ps output.
if ! { exec 3< /dev/tty; } 2>/dev/null; then exec 3<&0; fi
printf 'PFX password (Enter if none): ' >&2
IFS= read -r -s PW <&3; echo >&2
export PW

# OpenSSL 3 needs -legacy for RC2-encrypted PFX files; OpenSSL 1.x has no such flag.
LEGACY=()
if ! openssl pkcs12 -in "$IN" -nokeys -passin env:PW -out /dev/null 2>/dev/null; then
  if [[ $(openssl version | awk '{print $2}' | cut -d. -f1) -ge 3 ]] &&
     openssl pkcs12 -legacy -in "$IN" -nokeys -passin env:PW -out /dev/null 2>/dev/null; then
    LEGACY=(-legacy)
  else
    echo "ERROR: cannot open $IN - wrong password, damaged file, or OpenSSL too old" >&2
    exit 1
  fi
fi

# Piping through openssl x509 strips the "Bag Attributes / friendlyName / subject="
# preamble that -clcerts leaves in the output.
openssl pkcs12 ${LEGACY[@]+"${LEGACY[@]}"} -in "$IN" -passin env:PW -clcerts -nokeys \
  | openssl x509 -out "$OUT"

unset PW
chmod 644 "$OUT"

echo "Wrote $OUT"
openssl x509 -in "$OUT" -noout -subject -issuer -dates
SAN=$(openssl x509 -in "$OUT" -noout -text | grep -A1 "Subject Alternative Name" | tail -1 | sed 's/^ *//') || true
echo "SAN: ${SAN:-(none)}"
