#!/usr/bin/env bash
# Compare two PFX/PKCS#12 files to prove only the password changed.
#
#   ./compare_pfx.sh <old.pfx> <new.pfx>
#
# Byte-comparing the two files is useless: PKCS#12 re-encryption uses a fresh random
# salt and IV every time, so the files ALWAYS differ even when the contents are identical.
# This compares what actually matters:
#
#   - leaf certificate   SHA-256 fingerprint
#   - private key        SHA-256 of the derived public key (SPKI)
#   - CA chain           sorted set of SHA-256 fingerprints
#   - alias              friendlyName (what WebLogic/orapki look up)
#
# Exits 0 only if all four match. Neither input file is modified.
#
# Tested on bash 4.2 (OL7) and 5.x, OpenSSL 1.0.2 / 1.1.1 / 3.x.
set -euo pipefail
umask 077

OLD=${1:?usage: $0 <old.pfx> <new.pfx>}
NEW=${2:?usage: $0 <old.pfx> <new.pfx>}

for f in "$OLD" "$NEW"; do
  [[ -f $f ]] || { echo "ERROR: $f not found" >&2; exit 1; }
done
command -v openssl >/dev/null || { echo "ERROR: openssl not found" >&2; exit 1; }

SSL_VER=$(openssl version | awk '{print $2}')
SSL_MAJOR=${SSL_VER%%.*}

WORK=$(mktemp -d)
cleanup() {
  if [[ -d $WORK ]]; then
    find "$WORK" -type f -exec shred -u {} + 2>/dev/null || rm -rf "$WORK"/* 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
  fi
  unset OLD_PW NEW_PW 2>/dev/null || true
}
trap cleanup EXIT

# Read from the terminal when there is one, but fall back to stdin so this still
# works under cron, ssh -T, Ansible or a pipe.
if ! { exec 3< /dev/tty; } 2>/dev/null; then exec 3<&0; fi
ask() { # ask <varname> <prompt>
  local __v=$1
  printf '%s' "$2" >&2
  IFS= read -r -s "$__v" <&3 || { echo >&2; echo "ERROR: no password supplied" >&2; exit 1; }
  echo >&2
}

ask OLD_PW "Password for $OLD (Enter if none): "
ask NEW_PW "Password for $NEW (Enter if none): "
export OLD_PW NEW_PW

# ---------------------------------------------------------------------------
# probe <file> <env var name holding password> <tag>
# Writes $WORK/<tag>.{leaf,key,chain} and sets <TAG>_LEAF / _KEY / _CHAIN /
# _ALIAS / _SUBJ / _SERIAL / _END globals.
# ---------------------------------------------------------------------------
probe() {
  local file=$1 pwvar=$2 tag=$3
  local d="$WORK/$tag"
  mkdir -p "$d"

  local legacy=()
  if ! openssl pkcs12 -in "$file" -nokeys -passin "env:$pwvar" -out /dev/null 2>/dev/null; then
    if [[ $SSL_MAJOR -ge 3 ]] &&
       openssl pkcs12 -legacy -in "$file" -nokeys -passin "env:$pwvar" -out /dev/null 2>/dev/null; then
      legacy=(-legacy)
      echo "NOTE: $file uses legacy encryption (RC2) - reading with -legacy"
    else
      echo "ERROR: cannot open $file" >&2
      echo "       Wrong password, damaged file, or OpenSSL $SSL_VER too old for its encryption." >&2
      exit 1
    fi
  fi

  openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$file" -passin "env:$pwvar" \
    -clcerts -nokeys -out "$d/leaf.pem"
  openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$file" -passin "env:$pwvar" \
    -nocerts -nodes  -out "$d/key.pem"
  openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$file" -passin "env:$pwvar" \
    -cacerts -nokeys -out "$d/chain.pem" 2>/dev/null || : > "$d/chain.pem"

  grep -q "BEGIN CERTIFICATE" "$d/leaf.pem" || { echo "ERROR: no certificate in $file" >&2; exit 1; }

  local leaf key chain alias subj serial end keycount
  leaf=$(openssl x509 -in "$d/leaf.pem" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g')
  subj=$(openssl x509 -in "$d/leaf.pem" -noout -subject | sed 's/^subject=//')
  serial=$(openssl x509 -in "$d/leaf.pem" -noout -serial | sed 's/^serial=//')
  end=$(openssl x509 -in "$d/leaf.pem" -noout -enddate | sed 's/^notAfter=//')

  if grep -q "PRIVATE KEY" "$d/key.pem"; then
    key=$(openssl pkey -in "$d/key.pem" -pubout 2>/dev/null | openssl sha256 | awk '{print $NF}')
  else
    key="(no private key)"
  fi

  # Fingerprint each chain certificate, then sort so ordering differences don't
  # register as a mismatch.
  chain=""
  if grep -q "BEGIN CERTIFICATE" "$d/chain.pem" 2>/dev/null; then
    awk -v dir="$d" '
      /BEGIN CERTIFICATE/ { n++; out = dir "/ca" n ".pem" }
      n { print > out }
    ' "$d/chain.pem"
    chain=$(for c in "$d"/ca*.pem; do
              [[ -f $c ]] || continue
              openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g'
            done | sort | tr '\n' ',' )
  fi
  [[ -n $chain ]] || chain="(none)"

  alias=$(openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$file" -passin "env:$pwvar" \
            -nokeys -clcerts 2>/dev/null \
          | awk -F': ' '/friendlyName/{print $2; exit}' | tr -d '\r')
  [[ -n $alias ]] || alias="(none)"

  eval "${tag}_LEAF=\$leaf"
  eval "${tag}_KEY=\$key"
  eval "${tag}_CHAIN=\$chain"
  eval "${tag}_ALIAS=\$alias"
  eval "${tag}_SUBJ=\$subj"
  eval "${tag}_SERIAL=\$serial"
  eval "${tag}_END=\$end"
}

probe "$OLD" OLD_PW A
probe "$NEW" NEW_PW B

# ---------------------------------------------------------------------------
FAIL=0
row() { # row <label> <old> <new>
  local label=$1 a=$2 b=$3 verdict
  if [[ $a == "$b" ]]; then
    verdict="MATCH"
  else
    verdict="DIFFERENT"
    FAIL=1
  fi
  printf '%-22s %-10s\n' "$label" "$verdict"
  if [[ $verdict == DIFFERENT ]]; then
    printf '  old: %s\n' "$a"
    printf '  new: %s\n' "$b"
  fi
}

echo
echo "Comparing:"
echo "  old: $OLD"
echo "  new: $NEW"
echo
echo "Certificate identity"
printf '  subject   %s\n' "$A_SUBJ"
printf '  serial    %s\n' "$A_SERIAL"
printf '  expires   %s\n' "$A_END"
echo
echo "Content comparison"
row "leaf certificate" "$A_LEAF"  "$B_LEAF"
row "private key"      "$A_KEY"   "$B_KEY"
row "CA chain"         "$A_CHAIN" "$B_CHAIN"
row "alias"            "$A_ALIAS" "$B_ALIAS"
echo

# A missing key in either file is a failure regardless of whether they agree.
if [[ $A_KEY == "(no private key)" || $B_KEY == "(no private key)" ]]; then
  echo "ERROR: a private key is missing - old='$A_KEY' new='$B_KEY'" >&2
  FAIL=1
fi

# The passwords must actually differ, or nothing was re-protected.
if [[ $OLD_PW == "$NEW_PW" ]]; then
  echo "WARNING: both files open with the same password - the password was not changed"
fi

if [[ $FAIL -eq 0 ]]; then
  echo "RESULT: identical contents - only the password differs."
  echo "        Safe to deploy $NEW in place of $OLD."
  exit 0
else
  echo "RESULT: contents DIFFER - do not deploy $NEW as a replacement for $OLD." >&2
  exit 1
fi
