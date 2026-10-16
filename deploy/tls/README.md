Put the edge certificate here (mounted read-only into nginx):

- `fullchain.pem` — server certificate + intermediates for PATCHGATE_HOSTNAME
- `privkey.pem`   — private key (0600, owner root)

Connectors pin our CA/certificate at enrolment: plan renewals (RUNBOOK §8 "certificate expiry").
