# Phishing Awareness checklist

A small, student-friendly checklist for **recognising, reporting and responding to phishing attacks**. It supports the *CyberShield Campus* awareness campaign ("Think Before You Click").

## Why this project?

Phishing is one of the most common ways attackers steal credentials and deliver malware, because it targets people rather than technology. This toolkit gives users clear guidance, gives a Security Operations Centre (SOC) a consistent way to collect reports, and demonstrates good version-control practice on a security resource.

## What's inside

| Resource | Purpose | Location |
|----------|---------|----------|
| Red-flags guide | Explains phishing types and eight warning signs | [`docs/phishing-red-flags.md`](docs/phishing-red-flags.md) |
| Response checklist | Step-by-step actions before and after interacting with a message | [`checklists/phishing-response-checklist.md`](checklists/phishing-response-checklist.md) |
| Incident report template | Standard form for reporting to the SOC, with a 5-level severity scale | [`templates/phishing-incident-report-template.md`](templates/phishing-incident-report-template.md) |
| Worked example | A fictional completed report | [`examples/sample-phishing-incident-report.md`](examples/sample-phishing-incident-report.md) |
| URL red-flag checker | Python script that scores a link's text for phishing warning signs | [`scripts/url_red_flag_checker.py`](scripts/url_red_flag_checker.py) |
| Unit tests | Tests for the checker | [`tests/`](tests/) |

## Repository structure

```text
phishing-awareness-checklist/
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
├── docs/
│   └── phishing-red-flags.md
├── checklists/
│   └── phishing-response-checklist.md
├── templates/
│   └── phishing-incident-report-template.md
├── examples/
│   └── sample-phishing-incident-report.md
├── scripts/
│   └── url_red_flag_checker.py
└── tests/
    └── test_url_red_flag_checker.py
```

## Quick start

Requires **Python 3.8+**. There are no third-party dependencies.

```bash
git clone https://github.com/<2601597>/phishing-awareness-toolkit.git
cd phishing-awareness-checklist

# Check one or more links
python scripts/url_red_flag_checker.py "http://192.168.0.1:8080/secure-login-verify@account"

# Run the tests
python -m unittest discover -s tests -v
```

### Example output

```text
hxxps://www[.]example[.]com/
  Suspicion: LOW (score 0)

hxxp://campus-secure-login[.]example/verify@mail
  Suspicion: HIGH (score 6)
   - Contains '@' (everything before it is ignored by browsers)
   - Sensitive keyword in the domain name
   - Several hyphens in the domain name
   - Connection is not HTTPS

hxxp://192[.]168[.]0[.]1:8080/secure-login-verify@account
  Suspicion: HIGH (score 8)
   - Host is a raw IP address instead of a domain name
   - Contains '@' (everything before it is ignored by browsers)
   - Non-standard port number
   - Connection is not HTTPS
```

URLs are printed in *defanged* form (`hxxp`, `[.]`) so they are safe to paste into reports. The script exits with code `0` when every URL scores LOW and `1` otherwise, so it can be used in simple automation.

### What the checker looks for

Raw IP addresses, `@` symbols, punycode (look-alike) domains, URL shorteners, sensitive keywords in the domain, many subdomains or hyphens, very long URLs, unusual ports and plain HTTP.

## Limitations

- The checker only inspects the **text** of a URL. It does not visit the link, check reputation databases or inspect page content.
- A LOW result does **not** mean a link is safe. Treat it as a teaching aid, not a security control.
- The report template and checklist should be adapted to your organisation's own incident-response procedure and contact details.

## Roadmap

- [ ] Add a `--file` option to check a list of URLs
- [ ] Add JSON output for use in SOC tooling
- [ ] Add a short quiz for the awareness campaign

## Contributing and security

Contributions are welcome through pull requests. Please use fictional data and defanged links, and read [`SECURITY.md`](SECURITY.md) before contributing.

## Licence

Released under the [MIT Licence](LICENSE).
