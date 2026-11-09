# Security policy

## Reporting a vulnerability in Sentinel Scan

Please use GitHub's
[private vulnerability reporting](https://github.com/Terence-e/sentinel-scan/security/advisories/new)
rather than a public issue. Include the affected version, the steps to reproduce the problem and
its likely impact.

## Scope

In scope are flaws in this tool, for example a way for a malicious website to break out of scan
scope, run code on the scanning machine, or get unredacted secrets into a report.

Weaknesses that the tool finds in other people's websites are out of scope. Report those to the site
owner.

## Known limitation

Scope and private-address checks run before each new host is contacted. A target under an attacker's
control could change its DNS answer between that check and the connection, so do not treat the
private-address guard as a network security boundary.
