## What is measured

The kernel setting `/proc/sys/net/ipv4/ip_forward`, read every 15 seconds by the host script `omv-wg-metrics.sh` and stored as `omv_ip_forward`.

## When it is raised

- **Finding** when the value is 0 (forwarding off).
- **Advisory** when the value is missing, for example because the host script stopped.

## Why it matters

This server routes traffic from WireGuard clients (10.8.0.0/24) into the LAN. With forwarding off, your laptop and phone on the VPN can reach the server itself, but nothing else on the LAN.

## How to fix

1. Check the value: `sysctl net.ipv4.ip_forward`.
2. Turn it on now: `sysctl -w net.ipv4.ip_forward=1`.
3. It is made permanent by `/etc/sysctl.d/ip_forward.conf`. Check that the file still contains `net.ipv4.ip_forward = 1`.
4. If it keeps switching off, another file in `/etc/sysctl.d/` or a recent configuration change is overriding it. The history bar above shows when it changed.
