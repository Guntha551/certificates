# How to Execute the Certificate Scripts

## 1. Prerequisites

| Tool | Needed by | Check |
|---|---|---|
| bash 4.2+ | all scripts | `bash --version` |
| openssl 1.0.2 / 1.1.1 / 3.x | all scripts | `openssl version` |
| oci CLI (configured) | `oci_lb_update_cert.sh` | `oci lb load-balancer list --compartment-id <OCID>` |
| jq | `oci_lb_update_cert.sh` | `jq --version` |
| keytool (optional) | `change_pfx_password.sh` extra check | `keytool -help` |

## 2. Get the scripts

```bash
git clone https://github.com/Guntha551/certificates.git
cd certificates
chmod +x *.sh
```

## 3. Rules that apply to every script

- Run from a **private directory** (`chmod 700`) on a trusted server. PFX and PEM files contain private keys.
- Passwords are **prompted** (hidden input). Never put them on the command line.
- Scripts refuse to overwrite existing output files. Pick a new name or directory.
- Never commit `.pfx`, `.pem`, or `.key` files (blocked by `.gitignore`).
- Delete unencrypted keys when finished: `find <dir> -type f -exec shred -u {} + && rmdir <dir>`

## 4. Typical workflow (certificate renewal)

```
Received PFX  ->  change_pfx_password.sh  ->  compare_pfx.sh  ->  extract_pfx.sh  ->  oci_lb_update_cert.sh
```

### Step 1 - Change the PFX password (optional)

```bash
./change_pfx_password.sh WC_Onerheem_com_2026.pfx WC_Onerheem_com_2026_new.pfx
```
Prompts: current password, new password (twice). Output uses 3DES/SHA1 so older Java and orapki can read it. Original is untouched. Optional 3rd argument sets the alias.

### Step 2 - Prove only the password changed

```bash
./compare_pfx.sh WC_Onerheem_com_2026.pfx WC_Onerheem_com_2026_new.pfx
```
Prompts for both passwords. Exit code 0 and `RESULT: identical contents` means the new file is a safe replacement. Any `DIFFERENT` row means do not deploy.

### Step 3 - Extract PEM files

```bash
./extract_pfx.sh WC_Onerheem_com_2026_new.pfx ./pem_out
```
Creates in `./pem_out`: `certificate.pem`, `cacerts.pem`, `privatekey.pem` (PKCS#1), `privatekey_pkcs8.pem`, `fullchain.pem`, `certificate.cer`. It verifies the key matches the certificate and warns on expiry (<30 days) or a missing chain.

Lighter alternatives:
```bash
./extract_pem.sh file.pfx ./out      # certificate.pem, cacerts.pem, privatekey.pem only
./extract_cer.sh file.pfx out.cer    # public certificate only (not sensitive)
```

### Step 4 - Rotate the certificate on the OCI Load Balancer

Always **dry run first** (default; changes nothing):
```bash
./oci_lb_update_cert.sh \
  --lb-id ocid1.loadbalancer.oc1..xxxx \
  --listener <listener-name> \
  --cert-dir ./pem_out
```
Review the output, then apply:
```bash
./oci_lb_update_cert.sh \
  --lb-id ocid1.loadbalancer.oc1..xxxx \
  --listener <listener-name> \
  --cert-dir ./pem_out \
  --apply
```
Add `--delete-old` to remove the previous certificate bundle after the switch succeeds. Use `--name-prefix` to control the new bundle name (a timestamp is appended).

What it does: validates the PEMs, reads the live listener, creates a **new** certificate bundle (OCI bundles are immutable), repoints the listener keeping its current backend set, port, protocol and SSL settings, then confirms the listener references the new bundle.

### Step 5 - Verify from outside

```bash
echo | openssl s_client -connect <lb-host>:443 -servername <lb-host> 2>/dev/null \
  | openssl x509 -noout -subject -enddate -fingerprint -sha256
```
The SHA-256 must match the value printed by the script.

### Step 6 - Clean up

```bash
find ./pem_out -type f -exec shred -u {} + && rmdir ./pem_out
```

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `cannot open ... wrong password, damaged file, or OpenSSL too old` | Wrong password, or file needs a newer OpenSSL. RC2-encrypted PFX on OpenSSL 3 is handled automatically via `-legacy`. |
| `... already exists` | Output file or directory exists. Choose another name. |
| `private key does not match certificate` | The PFX is wrong or mismatched. Do not upload. |
| `no CA chain in the PFX` | Request the intermediate certificate from the issuer; Java clients fail path validation without it. |
| `listener '<name>' not found` | Script lists the valid listener names. Use one of them. |
| `generated name matches the current one` | Pass a different `--name-prefix`. |
| Old bundle cannot be deleted | Another listener still references it. |
