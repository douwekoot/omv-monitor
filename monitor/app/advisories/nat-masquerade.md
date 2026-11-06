## What is measured

How many rules in `iptables -t nat -S POSTROUTING` match `-o enp2s0 -j MASQUERADE`, stored as `omv_nat_masquerade`. Docker's own masquerade rules for its networks do not count.

## When it is raised

- **Finding** when no such rule exists.
- **Advisory** when the value is missing.

## Why it matters

VPN traffic leaves through enp2s0 with a 10.8.0.x source address. The router does not know that network, so without masquerading the replies never come back: VPN clients lose the LAN and the internet.

## How to fix

The rule is added by the `PostUp` line of the WireGuard interface `wgnet1` (managed by `wg-quick`).

1. Check: `iptables -t nat -S POSTROUTING | grep enp2s0`.
2. Restore it by restarting the interface: `systemctl restart wg-quick@wgnet1`. VPN connections drop for a few seconds, so do this from the LAN if you can.
3. If the rule disappears again, note when (the history bar above shows it) and compare with Docker restarts or network changes applied in OMV around that time.
