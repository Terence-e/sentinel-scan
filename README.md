# Sentinel Scan

A defensive website security scanner with safe defaults and clear reports. Point it at a site you
own or are authorized to test, and it produces a ranked list of findings with evidence and fixes.

> **Only scan systems you own or have explicit written permission to test.** Unauthorized scanning
> may be illegal. You are responsible for how you use this tool.

## What it checks

| Check | Tier | Looks for |
| --- | --- | --- |
| `transport` | Passive | HTTPS use, HTTP redirects, certificate validity, security headers, cookie flags |
| `frontend` | Passive | Admin routes in JavaScript, client-side authorization, debug code, source maps, third-party scripts |
| `secrets` | Passive | Private keys, cloud and SaaS tokens, database credentials, JWTs |
| `exposure` | Probe | `.env` files, `.git` metadata, `server-status`, public config files, admin and database panels |
| `access-control` | Probe | Account pages and APIs that answer without a login |
| `login` | Active, opt-in | Whether invalid logins are rejected and whether failed attempts are throttled |
| `network` | Network, opt-in | Exposed databases, remote access and other open ports |
| `urlscan` | Third-party, opt-in | Panel-like URLs seen by urlscan.io |

## Install

Requires Python 3.11 or newer. [Nmap](https://nmap.org/) is optional and improves `--network`.

```bash
git clone https://github.com/Terence-e/sentinel-scan.git
cd sentinel-scan
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install .
```

## Usage

```bash
# Prompts you to confirm authorization, then runs the passive and probe checks
sentinel-scan https://example.com

# Only load what a normal visitor loads
sentinel-scan https://example.com --passive-only

# Add login checks and a port scan
sentinel-scan https://example.com --active --network

# In CI: confirm authorization up front and fail the build on High or Critical findings
sentinel-scan https://staging.example.com --i-have-authorization --fail-on high
```

Reports are written to `./reports` as HTML and JSON by default. Use `--format html,json,txt` and
`--output DIR` to change that. Run `sentinel-scan --help` for every option.

| Exit code | Meaning |
| --- | --- |
| `0` | Scan completed |
| `1` | A finding reached the `--fail-on` threshold |
| `2` | Invalid input, or authorization was not confirmed |

## Safety by design

- **Explicit authorization:** a scan will not start until you confirm you are allowed to run it.
- **Least intrusive by default:** login submission, port scanning and third-party lookups are all
  opt-in.
- **Stays in scope:** requests are limited to the target host and its `www` twin, and redirects
  elsewhere are not followed.
- **Private networks are off by default:** targets that resolve to internal addresses need
  `--allow-private`.
- **Polite traffic:** requests are throttled and capped, with response sizes limited.
- **No brute force:** the login check sends at most five random invalid logins, and only with
  `--active`.
- **Redacted evidence:** reports mask secrets and omit cookie values, `.env` contents and personal
  data.
- **Hardened reports:** target-supplied text is escaped, and Nmap output is parsed with
  `defusedxml`.

Reports still describe weaknesses in a real system, so store them carefully. `reports/` is
ignored by Git.

## urlscan.io

`--urlscan` sends the target URL to [urlscan.io](https://urlscan.io/), submitted with private
visibility. Set your key in the `URLSCAN_API_KEY` environment variable. Never pass it on the command
line or commit it.

## Limitations

This is a lightweight heuristic scanner, not a penetration test or a replacement for a security
review. It does not crawl sites, log in, or test for injection flaws. Findings can be false
positives, so each one has a confidence rating. A clean report does not prove a site is secure.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
bandit -q -r src
```

The test suite runs real scans against a deliberately vulnerable local server and makes no external
requests.

## License

[MIT](LICENSE). See [SECURITY.md](SECURITY.md) to report a vulnerability in this tool.
