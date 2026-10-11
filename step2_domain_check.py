"""
Step 2: Domain reputation / typosquatting check.
Compares sender and link domains against a list of commonly-spoofed brands.
Builds on step1_parser.py.
"""

from difflib import SequenceMatcher
from urllib.parse import urlparse

# A short starter list. In a real project you'd pull a longer list from
# a public "top 1000 most-phished brands" dataset, but this is enough
# to prove the technique works.
KNOWN_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "facebook.com", "netflix.com", "bankofamerica.com",
    "chase.com", "wellsfargo.com", "dhl.com", "fedex.com",
]


def similarity(a, b):
    """
    Returns a score from 0 to 1 for how similar two strings are.
    1.0 = identical, 0.0 = completely different.
    Built on SequenceMatcher, which is Python's built-in diff algorithm.
    """
    return SequenceMatcher(None, a, b).ratio()


def strip_to_core_label(domain):
    """
    Pull out just the 'brand-ish' part of a domain, dropping the TLD
    and any extra words glued on with hyphens.

    Why: comparing whole strings like 'paypa1-alerts.com' against
    'paypal.com' scores LOW just because of the extra '-alerts' text,
    even though the brand-impersonating part is nearly identical.
    Attackers rely on exactly this padding trick to dodge naive checks.

    'paypa1-alerts.com' -> 'paypa1'
    'micros0ft-support.com' -> 'micros0ft'
    'paypal.com' -> 'paypal'
    """
    label = domain.split(".")[0]   # drop TLD and everything after it
    first_chunk = label.split("-")[0]  # take text before the first hyphen
    return first_chunk


def check_typosquatting(domain, brands=KNOWN_BRANDS, threshold=0.8):
    """
    Compare the CORE LABEL of `domain` against each known brand's core
    label. If it's suspiciously close but NOT an exact match, flag it.

    threshold=0.8 means "80% similar or more" counts as suspicious,
    now that we're comparing short, comparable brand-name fragments
    instead of full domain strings padded with extra words.
    """
    findings = []
    domain = domain.lower()
    domain_core = strip_to_core_label(domain)

    for brand in brands:
        brand_core = strip_to_core_label(brand)
        if brand == domain:
            # Exact match to a known brand = legitimate, not spoofed.
            continue
        score = similarity(domain_core, brand_core)
        if score >= threshold:
            findings.append({
                "suspected_brand": brand,
                "actual_domain": domain,
                "similarity": round(score, 2),
            })

    return findings


def domains_from_urls(urls):
    """Extract just the domain part from a list of full URLs."""
    domains = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.netloc:
            domains.add(parsed.netloc.lower())
    return domains


def run_domain_checks(from_domain, urls):
    """
    Check both the sender's domain and every domain found in the
    email's links. Returns a combined list of findings.
    """
    all_findings = []

    if from_domain:
        for finding in check_typosquatting(from_domain):
            finding["source"] = "sender (From address)"
            all_findings.append(finding)

    for domain in domains_from_urls(urls):
        for finding in check_typosquatting(domain):
            finding["source"] = f"link ({domain})"
            all_findings.append(finding)

    return all_findings


if __name__ == "__main__":
    # Quick standalone test with a few example domains.
    test_domains = [
        "paypa1-alerts.com",   # 1 -> l swap, should flag paypal.com
        "paypal.com",          # exact match, should NOT flag
        "micros0ft-support.com",  # 0 -> o swap, should flag microsoft.com
        "mycompany.com",       # unrelated, should NOT flag
    ]

    for d in test_domains:
        results = check_typosquatting(d)
        print(f"\n{d}:")
        if results:
            for r in results:
                print(f"  SUSPICIOUS -> looks like {r['suspected_brand']} "
                      f"(similarity {r['similarity']})")
        else:
            print("  no match found")