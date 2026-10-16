CA material mounted read-only at /etc/patchgate/ca in every PatchGate container:

- `siem-ca.pem`      — CA that signed the platform SIEM certificate (SIEM_CA_FILE)
- `internal-ca.pem`  — internal CAs trusted for outbound TLS (NODE_EXTRA_CA_CERTS)
- `codesign-ca.pem`  — Authenticode roots for osslsigncode (CODESIGN_CA_FILE); see docs/RUNBOOK.md §4.4
