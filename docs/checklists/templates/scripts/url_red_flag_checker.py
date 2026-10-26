#!/usr/bin/env python3
"""URL Red-Flag Checker: an educational phishing-awareness tool.

Looks at the *text* of a URL and reports common phishing warning signs.
It never visits the link and makes no network requests. The result is a
rough guide only: a "LOW" score does not prove a link is safe.

Usage:
    python scripts/url_red_flag_checker.py "http://192.168.0.1/login"
"""
import argparse
import ipaddress
import sys
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
              "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
KEYWORDS = ("login", "signin", "verify", "secure", "update", "account",
            "password", "banking", "confirm", "wallet")


def defang(url):
    """Make a URL safe to paste into a report (hxxp, [.])."""
    return url.replace("http", "hxxp", 1).replace(".", "[.]")


def parse(url):
    """Parse a URL, tolerating a missing scheme such as 'example.com/login'."""
    url = url.strip()
    return urlparse(url if "://" in url else "//" + url)


def analyse(url):
    """Return (score, flags) for a URL."""
    parsed = parse(url)
    host = (parsed.hostname or "").lower()
    score, flags = 0, []

    def add(points, message):
        nonlocal score
        score += points
        flags.append(message)

    try:
        ipaddress.ip_address(host)
        add(3, "Host is a raw IP address instead of a domain name")
    except ValueError:
        pass
    if "@" in url:
        add(3, "Contains '@' (everything before it is ignored by browsers)")
    if "xn--" in host:
        add(2, "Punycode domain (possible look-alike characters)")
    if host in SHORTENERS:
        add(2, "URL shortener hides the real destination")
    if any(word in host for word in KEYWORDS):
        add(1, "Sensitive keyword in the domain name")
    if host.count(".") > 3:
        add(1, "Unusually many subdomains")
    if host.count("-") >= 2:
        add(1, "Several hyphens in the domain name")
    if len(url) > 75:
        add(1, "Very long URL")
    if parsed.port not in (None, 80, 443):
        add(1, "Non-standard port number")
    if parsed.scheme == "http":
        add(1, "Connection is not HTTPS")
    return score, flags


def verdict(score):
    if score >= 4:
        return "HIGH"
    if score >= 2:
        return "MEDIUM"
    return "LOW"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check URLs for phishing red flags.")
    parser.add_argument("urls", nargs="+", help="one or more URLs to check")
    args = parser.parse_args(argv)

    worst = "LOW"
    for url in args.urls:
        score, flags = analyse(url)
        level = verdict(score)
        print(f"{defang(url)}\n  Suspicion: {level} (score {score})")
        for flag in flags:
            print(f"   - {flag}")
        if level != "LOW":
            worst = level
    return 0 if worst == "LOW" else 1


if __name__ == "__main__":
    sys.exit(main())
