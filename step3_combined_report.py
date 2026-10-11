"""
Step 3: Combine Step 1 (parsing) and Step 2 (domain checks) into one
evidence report. This is the object we'll eventually hand to the LLM.
"""

from email.utils import parseaddr

from step1_parser import analyze_email
from step2_domain_check import run_domain_checks


def from_domain_of(headers):
    """Extract just the domain from the From header, e.g. 'paypal.com'."""
    _, addr = parseaddr(headers.get("From", ""))
    return addr.split("@")[-1].lower() if "@" in addr else None


def build_report(raw_email_text):
    """
    Run the full Step 1 + Step 2 pipeline and return one combined
    evidence report as a dictionary.
    """
    parsed = analyze_email(raw_email_text)
    sender_domain = from_domain_of(parsed["headers"])
    domain_findings = run_domain_checks(sender_domain, parsed["urls"])

    return {
        "headers": parsed["headers"],
        "sender_mismatches": parsed["sender_mismatches"],
        "auth_results": parsed["auth_results"],
        "body": parsed["body"],
        "urls": parsed["urls"],
        "domain_findings": domain_findings,
    }


def print_report(report):
    """Pretty-print the report so it's easy to read in the terminal."""
    print("=" * 60)
    print("PHISHING TRIAGE REPORT")
    print("=" * 60)

    print("\n[HEADERS]")
    for k, v in report["headers"].items():
        print(f"  {k}: {v}")

    print("\n[SENDER MISMATCHES]")
    if report["sender_mismatches"]:
        for m in report["sender_mismatches"]:
            print(f"  - {m}")
    else:
        print("  none")

    print("\n[AUTH RESULTS]")
    for k, v in report["auth_results"].items():
        print(f"  {k}: {v}")

    print("\n[DOMAIN / TYPOSQUATTING FINDINGS]")
    if report["domain_findings"]:
        for f in report["domain_findings"]:
            print(f"  - {f['actual_domain']} looks like {f['suspected_brand']} "
                  f"(similarity {f['similarity']}, source: {f['source']})")
    else:
        print("  none")

    print("\n[URLS FOUND]")
    for u in report["urls"]:
        print(f"  - {u}")

    print("\n" + "=" * 60)


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
    report = build_report(sample_email)
    print_report(report)