## What is measured

The link state (`node_network_carrier`) of enp2s0 (the LAN card) and wgnet1 (the WireGuard interface). Carrier is used instead of "up" because wgnet1 always reports its state as unknown. The unused wireless card wlp3s0 is ignored.

## When it is raised

- **Finding** when one of these two has no carrier.

## Why it matters

- enp2s0 down: the server is off the network. You may only see this afterwards, because the page itself is served over that link.
- wgnet1 down: no VPN access.

## How to fix

1. enp2s0: check the cable and the switch or router port. At the console, `ip link show enp2s0`.
2. wgnet1: `wg show wgnet1` and `systemctl status wg-quick@wgnet1`, then `systemctl restart wg-quick@wgnet1`.
3. The Recovery page in the wiki has the full console procedure.
