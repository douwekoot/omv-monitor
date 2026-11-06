## What is measured

Whether traffic to the server that no rule allows is refused, stored as `omv_input_policy_accept`. The value is 1 (open) when `iptables -S INPUT` shows `-P INPUT ACCEPT` and there is no catch-all `-A INPUT -j REJECT` or `-j DROP` rule. OMV's firewall leaves the policy at ACCEPT and ends with such a rule, so either form counts as default deny. This covers IPv4 traffic addressed to the server itself.

## When it is raised

- **Advisory** when there is no default deny. It is not a finding: nothing is broken, and the LAN is trusted.
- **Advisory** when the value is missing.

## Why it matters

Without a default deny, every listening port (see the wiki page Listening ports) answers anything that can reach the server. That includes SSH, Samba and this monitor on 8443, should a port ever be forwarded by mistake.

## How to fix

Use OMV: Network, Firewall. Add these INPUT rules (IPv4) in this order, and press Apply only when all of them are in:

| # | Action | Protocol | Source | Destination port | Extra options |
|---|---|---|---|---|---|
| 1 | ACCEPT | All | | | `-i lo` |
| 2 | ACCEPT | All | | | `-m conntrack --ctstate ESTABLISHED,RELATED` |
| 3 | ACCEPT | All | `192.168.1.0/24` | | |
| 4 | ACCEPT | All | `10.8.0.0/24` | | |
| 5 | ACCEPT | UDP | | `51820` | |
| 6 | ACCEPT | ICMP | | | |
| 7 | REJECT | All | | | |

OMV keeps these across reboots and leaves Docker's and WireGuard's FORWARD and NAT rules alone. If a change locks you out, remove rule 7 from the console, or run `iptables -F INPUT`.
