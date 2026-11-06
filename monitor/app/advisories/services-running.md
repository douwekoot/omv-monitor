## What is measured

The host script checks every 15 seconds whether each service runs, stored as `omv_service_active`:

- Each service listed under `[[services]]` in `config/monitor.toml`.
- Running means `systemctl is-active` succeeds, or a Docker container of that name is running.

## When it is raised

- **Finding** when a service is not running.
- **Advisory** when a service has no value.

## Why it matters

Each listed service is something you use, such as file shares, media, a web front end or remote access. A stopped one usually means that use is broken until it is started again.

## How to fix

1. See why it stopped: `systemctl status <name>` and `journalctl -u <name> -n 50`. For a container: `docker ps -a --filter name=<name>` and `docker logs --tail 50 <name>`.
2. Start it again: `systemctl restart <name>`, or `docker start <name>`.
3. If the service is switched off in OMV on purpose, it stays stopped; turn it on in the OMV web interface instead.
