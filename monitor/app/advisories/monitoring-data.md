## What is measured

Whether Prometheus answered every query this page needed.

## When it is raised

- **Finding** when one or more queries failed. Values on the page may then be incomplete or missing, and other rules may show "not reported".

## Why it matters

Without data the other rules cannot tell you anything, so a quiet page could hide a real problem.

## How to fix

1. On the server: `cd /opt/omv-monitor && docker compose ps`. All four containers should be running.
2. Look at Prometheus: `docker compose logs --tail 50 prometheus`.
3. Start what is down: `docker compose up -d`.
4. Check free disk space with `df -h`; Prometheus stops writing when the disk is full.
