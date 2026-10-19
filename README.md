# certificates

Shell scripts for working with PFX (PKCS#12) certificates and rotating OCI Load Balancer certificates.
All scripts prompt for passwords (never on the command line) and need `openssl`; `oci_lb_update_cert.sh` also needs `oci` and `jq`.

| Script | Purpose |
|---|---|
| `change_pfx_password.sh <in.pfx> [out.pfx] [alias]` | Re-protect a PFX with a new password (3DES/SHA1 for older Java/orapki), preserving the alias |
| `compare_pfx.sh <old.pfx> <new.pfx>` | Prove two PFX files hold the same cert, key, chain and alias (only the password differs) |
| `extract_cer.sh <file.pfx> [out.cer]` | Extract the public certificate as Base64 `.cer` |
| `extract_pem.sh <file.pfx> [dir]` | Extract `certificate.pem`, `cacerts.pem`, `privatekey.pem` (PKCS#1, unencrypted) |
| `extract_pfx.sh <file.pfx> [dir]` | Full clean PEM set for OCI LB upload (also PKCS#8 key, fullchain, DER `.cer`) with validation |
| `oci_lb_update_cert.sh --lb-id <OCID> --listener <name> --cert-dir <dir> [--apply] [--delete-old]` | Rotate the cert on an OCI LB listener (dry run by default) |

Typical flow: `change_pfx_password.sh` -> `compare_pfx.sh` -> `extract_pfx.sh` -> `oci_lb_update_cert.sh`.

**Never commit `.pfx`, `.pem`, `.key` files.** See `.gitignore`.
