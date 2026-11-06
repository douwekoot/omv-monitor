## What is measured

The host script runs a simulated upgrade (`apt-get -s upgrade`) and stores the number of packages that would be upgraded as `omv_apt_upgrades_pending`.

## When it is raised

- **Advisory** when one or more upgrades are pending, or when the count is not reported.

## Why it matters

Pending upgrades often include security fixes. The longer they wait, the longer known holes stay open.

## How to fix

1. Open OMV: System, Update Management, and install the updates.
2. If the count is not reported, check that `apt-get` works for the metrics script.
