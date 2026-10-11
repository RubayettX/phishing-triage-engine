"""
Step 1: Deterministic email parser (no AI yet).
Extracts headers, auth results, body text, and URLs from raw email text.
"""

from email import message_from_string, policy
from email.utils import parseaddr
import re
from bs4 import BeautifulSoup


def parse_headers(msg):
    """Pull out the headers a SOC analyst checks first."""
    headers = {}
    for name in ["From", "To", "Subject", "Return-Path", "Reply-To",
                 "Date", "Authentication-Results"]:
        value = msg.get(name)
        if value:
            headers[name] = str(value).strip()
    return headers

def check_sender_mismatch(headers):
    """
    Compare From vs Return-Path vs Reply-To domains.
    A mismatch doesn't prove phishing (mailing lists do this legitimately),
    but it's a signal worth flagging.
    """
    findings = []

    def domain_of(header_value):
        _, addr = parseaddr(header_value or "")
        return addr.split("@")[-1].lower() if "@" in addr else None

    from_domain = domain_of(headers.get("From"))
    return_domain = domain_of(headers.get("Return-Path"))
    reply_domain = domain_of(headers.get("Reply-To"))

    if from_domain and return_domain and from_domain != return_domain:
        findings.append(
            f"From domain ({from_domain}) differs from Return-Path domain ({return_domain})"
        )
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(
            f"From domain ({from_domain}) differs from Reply-To domain ({reply_domain})"
        )
    return findings


def check_auth_results(headers):
    """
    Parse the Authentication-Results header for spf/dkim/dmarc pass/fail.
    This header is added by the RECEIVING mail server, so it's much harder
    for an attacker to fake than the From address.
    """
    auth_header = headers.get("Authentication-Results", "")
    results = {}
    for mechanism in ["spf", "dkim", "dmarc"]:
        match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
        results[mechanism] = match.group(1).lower() if match else "not found"
    return results


def extract_body_and_urls(msg):
    """Walk the email parts, strip HTML, and pull out all links."""
    plain_parts, html_parts = [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            plain_parts.append(part.get_content())
        elif ctype == "text/html":
            html_parts.append(part.get_content())

    urls = []
    html_text = ""
    for html in html_parts:
        soup = BeautifulSoup(html, "html.parser")
        for a in soup.find_all("a", href=True):
            if a["href"].startswith(("http://", "https://")):
                urls.append(a["href"])
        html_text += soup.get_text(separator="\n")

    body = "\n".join(plain_parts).strip() or html_text.strip()

    # Also catch bare URLs written as plain text (not inside <a> tags)
    url_regex = re.compile(r'https?://[^\s<>"\')\]]+')
    urls += url_regex.findall(body)

    # Deduplicate while keeping order
    urls = list(dict.fromkeys(urls))

    return body, urls


def analyze_email(raw_text):
    """Run the full Step 1 pipeline and return a findings dict."""
    msg = message_from_string(raw_text.lstrip(), policy=policy.default)

    headers = parse_headers(msg)
    mismatches = check_sender_mismatch(headers)
    auth = check_auth_results(headers)
    body, urls = extract_body_and_urls(msg)

    return {
        "headers": headers,
        "sender_mismatches": mismatches,
        "auth_results": auth,
        "body": body,
        "urls": urls,
    }


if __name__ == "__main__":
    sample_email = """From: "PayPal Support" <security@paypa1-alerts.com>
To: victim@example.com
Subject: Urgent: Your account will be suspended
Return-Path: <bounce@mailer-track.xyz>
Reply-To: scammer@paypa1-alerts.com
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=paypa1-alerts.com; dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: text/html; charset=utf-8

<html><body>
<p>Dear user, your account has been locked. Click below within 24 hours
to avoid permanent suspension.</p>
<a href="http://paypa1-alerts.com/login?id=42">Verify My Account</a>
</body></html>
"""
    result = analyze_email(sample_email)

    print("HEADERS:")
    for k, v in result["headers"].items():
        print(f"  {k}: {v}")

    print("\nSENDER MISMATCHES:")
    for m in result["sender_mismatches"]:
        print(f"  - {m}")

    print("\nAUTH RESULTS:")
    for k, v in result["auth_results"].items():
        print(f"  {k}: {v}")

    print("\nBODY TEXT:")
    print(" ", result["body"].replace("\n", " "))

    print("\nURLS FOUND:")
    for u in result["urls"]:
        print(f"  - {u}")