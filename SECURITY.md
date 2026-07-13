# Security Policy

## Supported versions

PCAP Hunter is developed on a single rolling `main` branch — there is no
long-term-support branch. Security fixes are applied to `main` and released
as the next version; only the latest released version is supported.

| Version | Supported |
|---------|-----------|
| latest (`main`) | yes |
| older releases  | no  |

## Reporting a vulnerability

Please do not open a public GitHub issue for security vulnerabilities.

Instead, report privately using one of:

- Open a private GitHub Security Advisory for this repository
  (repo → **Security** tab → **Advisories** → **Report a vulnerability**), or
- Email the maintainer directly (see the repository's commit history /
  GitHub profile for a current contact) with a description of the issue,
  affected version/commit, and reproduction steps.

Please include enough detail to reproduce the issue (PCAP sample or steps,
affected module/endpoint, expected vs. actual behavior). We'll acknowledge
reports and follow up with next steps as the issue is triaged.

## Scope and hardening expectations

A few things are worth calling out explicitly because of what this tool does:

- **PCAP Hunter parses hostile, untrusted input by design.** PCAP files come
  from real (potentially adversary-controlled) network traffic, and the
  pipeline runs several native tools (Zeek, tshark, PyShark) and file-format
  parsers (TLS/X.509, YARA) against that input. Treat any parser crash,
  memory-safety issue, or resource-exhaustion bug in these paths as a
  security-relevant finding, not just a bug.
- **The app makes outbound network calls.** OSINT enrichment (VirusTotal,
  AbuseIPDB, GreyNoise, OTX, Shodan, WHOIS, reverse DNS) and LLM calls (LM
  Studio, OpenAI, Anthropic) send indicators and/or sanitized context to
  third-party or self-hosted endpoints. If you operate in an environment
  where that egress is sensitive, review `app/security/opsec.py` and the
  Config tab before enabling providers, and consider network-level egress
  controls.
- **The Streamlit UI has no built-in authentication.** It is designed to run
  as a local, single-analyst tool. Do not expose it directly to an untrusted
  network or the public internet. If remote/shared access is required, put
  it behind a reverse proxy that terminates TLS and enforces authentication
  (e.g., an OAuth2 proxy, SSO gateway, or VPN-only access) rather than
  relying on Streamlit itself for access control. The same applies to the
  optional integrations API (`app/api/`) — run it behind a proxy/firewall
  and use its API-key auth; do not expose it unauthenticated to the internet.
- **Config secrets are encrypted at rest but machine-bound.** API keys saved
  via the Config tab are encrypted with a PBKDF2 key derived from local
  machine identifiers (see `ConfigManager` in `CLAUDE.md`). Don't commit
  `~/.pcap_hunter_config.json` or `.env` files, and don't share them across
  machines expecting the encryption to travel with them.

## Dependency scanning

Dependencies are scanned on every push/PR via an advisory `pip-audit` CI job
(see `.github/workflows/ci.yml`) and kept up to date via Dependabot
(`.github/dependabot.yml`, weekly for both `pip` and GitHub Actions). Findings
there don't block merges automatically but are reviewed as part of normal
maintenance.
