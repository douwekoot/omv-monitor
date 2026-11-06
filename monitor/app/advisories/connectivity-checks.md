## What is measured

The blackbox exporter probes from this server every 15 seconds:

- `ping 192.168.1.1`: the router.
- `ping 1.1.1.1`: an internet address.
- `dns 1.1.1.1`: a DNS lookup of example.org at 1.1.1.1.

Each probe stores `probe_success` (1 or 0) and its response time.

## When it is raised

- **Finding** when a probe fails (`probe_success` is 0).
- **Advisory** when a probe has no value at all.

## Why it matters

- Router down: the server has lost the LAN.
- 1.1.1.1 down while the router answers: the internet connection or the ISP is down.
- DNS down while ping 1.1.1.1 works: name lookups fail, so updates and anything that connects out by name can break.

## How to fix

1. Open the failing check above for its history. A single short failure shows as a partly filled segment in the bar; act only if it stays down.
2. Router: check the cable and the enp2s0 interface page, then the router itself.
3. Internet: if the router answers, check the router's internet status or the ISP.
4. DNS: on the server, `dig @1.1.1.1 example.org` shows whether lookups work outside the monitor.
