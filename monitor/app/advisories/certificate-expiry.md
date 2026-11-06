## What is measured

The host script reads the expiry date of the TLS certificate and stores it as `omv_cert_expiry_timestamp_seconds`.

## When it is raised

- **Advisory** when the certificate expires within 30 days.
- **Finding** when it expires within 7 days, or has already expired.

## Why it matters

An expired certificate makes browsers refuse the site, so the monitor and anything served with the same certificate stop being reachable without a warning click-through.

## How to fix

1. Renew or reissue the certificate and replace the files in the configured location.
2. Restart whatever serves it, for example `docker compose restart web` in `/opt/omv-monitor`.
3. Check that the expiry date moves forward on the next metrics run.
