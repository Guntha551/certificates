#!/usr/bin/env bash
# Rotate the TLS certificate on an OCI Load Balancer listener.
#
#   ./oci_lb_update_cert.sh --lb-id <OCID> --listener <name> --cert-dir <dir> [--apply] [--delete-old]
#
# WHY THIS IS NOT A ONE-LINER
#
# 1. OCI load balancer certificate bundles are IMMUTABLE. `oci lb certificate` offers only
#    create, delete and list - there is no update - and --certificate-name is documented as
#    "unique and it cannot be changed". Rotation therefore means: create a NEW bundle under a
#    NEW name, repoint the listener at it, then delete the old bundle.
#
# 2. `oci lb listener update` lists --default-backend-set-name, --port and --protocol as
#    REQUIRED, even when the only thing changing is the certificate. Omitting them risks
#    rewriting the listener with defaults. This script reads the live listener first and
#    re-sends its current values unchanged.
#
# Defaults to a DRY RUN. Nothing is created, changed or deleted without --apply.
#
# Input is the output directory of extract_pfx.sh: certificate.pem, privatekey.pem and
# (optionally) cacerts.pem.
set -euo pipefail
umask 077

LB_ID=""
LISTENER=""
CERT_DIR=""
NAME_PREFIX=""
APPLY=0
DELETE_OLD=0

usage() {
  cat >&2 <<'EOF'
usage: oci_lb_update_cert.sh --lb-id <OCID> --listener <name> --cert-dir <dir> [options]

  --lb-id       OCID of the load balancer                       (required)
  --listener    name of the listener to repoint                 (required)
  --cert-dir    directory from extract_pfx.sh                   (required)
  --name-prefix certificate bundle name prefix
                (default: derived from the certificate CN)
  --apply       actually create/update/delete; default is a dry run
  --delete-old  delete the previously referenced bundle after a successful switch
  -h, --help    this message
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --lb-id)       LB_ID=${2:?}; shift 2 ;;
    --listener)    LISTENER=${2:?}; shift 2 ;;
    --cert-dir)    CERT_DIR=${2:?}; shift 2 ;;
    --name-prefix) NAME_PREFIX=${2:?}; shift 2 ;;
    --apply)       APPLY=1; shift ;;
    --delete-old)  DELETE_OLD=1; shift ;;
    -h|--help)     usage ;;
    *) echo "ERROR: unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n $LB_ID && -n $LISTENER && -n $CERT_DIR ]] || usage

for c in oci openssl jq; do
  command -v "$c" >/dev/null || { echo "ERROR: $c not found in PATH" >&2; exit 1; }
done

CERT="$CERT_DIR/certificate.pem"
KEY="$CERT_DIR/privatekey.pem"
CHAIN="$CERT_DIR/cacerts.pem"

[[ -f $CERT ]] || { echo "ERROR: $CERT not found" >&2; exit 1; }
[[ -f $KEY  ]] || { echo "ERROR: $KEY not found" >&2; exit 1; }

run() { # run <description> <command...>
  if [[ $APPLY -eq 1 ]]; then
    echo "+ $*"
    "$@"
  else
    echo "[dry run] would run:"
    printf '   '
    printf ' %q' "$@"
    echo
  fi
}

# ---------------------------------------------------------------------------
echo "== 1. Validate the PEM files locally (before touching OCI)"

head -1 "$CERT" | grep -q -- "-----BEGIN CERTIFICATE-----" \
  || { echo "ERROR: $CERT does not start with a certificate PEM header." >&2
       echo "       Strip bag attributes - use extract_pfx.sh." >&2; exit 1; }
head -1 "$KEY" | grep -qE -- "-----BEGIN (RSA |EC )?PRIVATE KEY-----" \
  || { echo "ERROR: $KEY does not start with a private key PEM header." >&2; exit 1; }
grep -q "ENCRYPTED" "$KEY" \
  && { echo "ERROR: $KEY is encrypted. OCI needs an unencrypted key, or pass --passphrase." >&2
       exit 1; }

CERT_HASH=$(openssl x509 -in "$CERT" -noout -pubkey | openssl sha256 | awk '{print $NF}')
KEY_HASH=$(openssl pkey -in "$KEY" -pubout | openssl sha256 | awk '{print $NF}')
[[ $CERT_HASH == "$KEY_HASH" ]] \
  || { echo "ERROR: private key does not match certificate - refusing to upload." >&2; exit 1; }

CN=$(openssl x509 -in "$CERT" -noout -subject \
     | sed -n 's/.*CN *= *\([^,/]*\).*/\1/p' | tr -d ' ')
NOT_AFTER=$(openssl x509 -in "$CERT" -noout -enddate | sed 's/notAfter=//')
FINGERPRINT=$(openssl x509 -in "$CERT" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g')

openssl x509 -in "$CERT" -noout -checkend 0 >/dev/null 2>&1 \
  || { echo "ERROR: certificate expired on $NOT_AFTER - refusing to upload." >&2; exit 1; }

CHAIN_ARGS=()
if [[ -f $CHAIN ]]; then
  CHAIN_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CHAIN" || true)
  CHAIN_ARGS=(--ca-certificate-file "$CHAIN")
else
  CHAIN_COUNT=0
  echo "WARNING: no cacerts.pem - uploading without a CA chain."
  echo "         Java and some mobile clients will fail path validation."
fi

echo "  CN              : ${CN:-unknown}"
echo "  expires         : $NOT_AFTER"
echo "  SHA-256         : $FINGERPRINT"
echo "  chain certs     : $CHAIN_COUNT"
echo "  key matches cert: YES"

# ---------------------------------------------------------------------------
echo
echo "== 2. Read the current listener (its values are re-sent unchanged)"

# There is no `oci lb listener get`; listeners live inside the load balancer object.
LB_JSON=$(oci lb load-balancer get --load-balancer-id "$LB_ID")
LISTENER_JSON=$(printf '%s' "$LB_JSON" | jq -e --arg n "$LISTENER" '.data.listeners[$n]') \
  || { echo "ERROR: listener '$LISTENER' not found on this load balancer." >&2
       echo "       Listeners present:" >&2
       printf '%s' "$LB_JSON" | jq -r '.data.listeners | keys[]' | sed 's/^/         /' >&2
       exit 1; }

# Note: `X // empty` is wrong here - jq treats `false` as falsy, so a
# verify-peer-certificate of false would come back empty and be silently dropped from the
# update. Test for null explicitly instead.
jqv() { printf '%s' "$LISTENER_JSON" | jq -r "if ($1) == null then \"\" else ($1) end"; }

CUR_BACKEND=$(jqv '."default-backend-set-name"')
CUR_PORT=$(jqv '.port')
CUR_PROTOCOL=$(jqv '.protocol')
CUR_CERT_NAME=$(jqv '."ssl-configuration"."certificate-name"')
CUR_VERIFY_DEPTH=$(jqv '."ssl-configuration"."verify-depth"')
CUR_VERIFY_PEER=$(jqv '."ssl-configuration"."verify-peer-certificate"')
CUR_CIPHER=$(jqv '."ssl-configuration"."cipher-suite-name"')
CUR_PROTOCOLS=$(printf '%s' "$LISTENER_JSON" | jq -c '."ssl-configuration".protocols // empty')
ETAG=$(printf '%s' "$LB_JSON" | jq -r '.etag // empty')

[[ -n $CUR_BACKEND && -n $CUR_PORT && -n $CUR_PROTOCOL ]] \
  || { echo "ERROR: could not read backend set / port / protocol from the listener." >&2
       echo "       Refusing to run an update that would omit required properties." >&2; exit 1; }

echo "  backend set     : $CUR_BACKEND"
echo "  port            : $CUR_PORT"
echo "  protocol        : $CUR_PROTOCOL"
echo "  current cert    : ${CUR_CERT_NAME:-(none - listener is not using SSL)}"
echo "  cipher suite    : ${CUR_CIPHER:-(default)}"

# ---------------------------------------------------------------------------
NEW_CERT_NAME="${NAME_PREFIX:-${CN:-cert}}"
# Bundle names allow only alphanumerics, dashes and underscores.
NEW_CERT_NAME=$(printf '%s' "$NEW_CERT_NAME" | tr '.' '_' | tr -cd '[:alnum:]_-')
NEW_CERT_NAME="${NEW_CERT_NAME}_$(date +%Y%m%d%H%M%S)"

if [[ $NEW_CERT_NAME == "$CUR_CERT_NAME" ]]; then
  echo "ERROR: generated name matches the current one - pass a different --name-prefix." >&2
  exit 1
fi

echo
echo "== 3. Create the new certificate bundle: $NEW_CERT_NAME"
run oci lb certificate create \
  --load-balancer-id "$LB_ID" \
  --certificate-name "$NEW_CERT_NAME" \
  --public-certificate-file "$CERT" \
  --private-key-file "$KEY" \
  ${CHAIN_ARGS[@]+"${CHAIN_ARGS[@]}"} \
  --wait-for-state SUCCEEDED

# ---------------------------------------------------------------------------
echo
echo "== 4. Repoint listener '$LISTENER' at the new bundle"

UPDATE_ARGS=(
  oci lb listener update
  --load-balancer-id "$LB_ID"
  --listener-name "$LISTENER"
  --default-backend-set-name "$CUR_BACKEND"
  --port "$CUR_PORT"
  --protocol "$CUR_PROTOCOL"
  --ssl-certificate-name "$NEW_CERT_NAME"
  --force
)
[[ -n $CUR_VERIFY_DEPTH ]] && UPDATE_ARGS+=(--ssl-verify-depth "$CUR_VERIFY_DEPTH")
[[ -n $CUR_VERIFY_PEER  ]] && UPDATE_ARGS+=(--ssl-verify-peer-certificate "$CUR_VERIFY_PEER")
[[ -n $CUR_CIPHER       ]] && UPDATE_ARGS+=(--cipher-suite-name "$CUR_CIPHER")
[[ -n $CUR_PROTOCOLS    ]] && UPDATE_ARGS+=(--protocols "$CUR_PROTOCOLS")
UPDATE_ARGS+=(--wait-for-state SUCCEEDED)

run "${UPDATE_ARGS[@]}"

# ---------------------------------------------------------------------------
echo
echo "== 5. Confirm the listener is serving the new bundle"

if [[ $APPLY -eq 1 ]]; then
  AFTER=$(oci lb load-balancer get --load-balancer-id "$LB_ID" \
          | jq -r --arg n "$LISTENER" \
              '.data.listeners[$n]."ssl-configuration"."certificate-name" // empty')
  if [[ $AFTER == "$NEW_CERT_NAME" ]]; then
    echo "  listener now references: $AFTER"
  else
    echo "ERROR: listener references '$AFTER', expected '$NEW_CERT_NAME'." >&2
    echo "       Not deleting the old bundle. Investigate before retrying." >&2
    exit 1
  fi
else
  echo "[dry run] would re-read the load balancer and confirm the listener references"
  echo "          $NEW_CERT_NAME before considering any deletion"
fi

# ---------------------------------------------------------------------------
if [[ $DELETE_OLD -eq 1 && -n $CUR_CERT_NAME ]]; then
  echo
  echo "== 6. Delete the old bundle: $CUR_CERT_NAME"
  echo "  NOTE: a bundle still referenced by another listener cannot be deleted."
  run oci lb certificate delete \
    --load-balancer-id "$LB_ID" \
    --certificate-name "$CUR_CERT_NAME" \
    --force \
    --wait-for-state SUCCEEDED
elif [[ -n $CUR_CERT_NAME ]]; then
  echo
  echo "Old bundle '$CUR_CERT_NAME' left in place. Remove it once the new one is confirmed good:"
  echo "  oci lb certificate delete --load-balancer-id $LB_ID \\"
  echo "    --certificate-name $CUR_CERT_NAME --force"
fi

echo
if [[ $APPLY -eq 1 ]]; then
  echo "DONE. Verify from outside:"
  echo "  echo | openssl s_client -connect <lb-host>:$CUR_PORT -servername <lb-host> 2>/dev/null \\"
  echo "    | openssl x509 -noout -subject -enddate -fingerprint -sha256"
  echo "  Expected SHA-256: $FINGERPRINT"
else
  echo "DRY RUN - nothing was changed. Re-run with --apply to execute."
fi
