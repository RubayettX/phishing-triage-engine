# Phishing Triage Engine

An AI-assisted triage tool for phishing emails, built around a core security principle: deterministic evidence first, AI explanation second. The system never asks an LLM to "decide" whether an email is malicious, it runs fast, auditable checks locally, and only hands the results of those checks to Gemini to summarize into a SOC-style verdict.

## Why this design?

LLMs are unreliable at raw detection, they hallucinate, they can be manipulated by prompt injection hidden in the email body, and their reasoning isn't auditable. So this project splits the work:

1. Deterministic layer (no AI, 100% auditable): parses headers, checks SPF/DKIM/DMARC authentication results, flags sender/domain mismatches, and detects typosquatted domains (e.g. paypa1-alerts.com impersonating paypal.com).
2. AI layer (Gemini): takes the evidence already gathered and writes a clear verdict, risk score, and recommended containment steps. It explains the evidence, it doesn't invent new findings.

The email body is explicitly treated as untrusted, attacker-controlled input. The system prompt instructs Gemini to ignore any instructions embedded inside the email itself, a defense against prompt-injection attacks.

## Architecture

Raw email text
to step1_parser.py: headers, SPF/DKIM/DMARC, sender mismatches, body, URLs
to step2_domain_check.py: typosquat detection against known brands
to step3_combined_report.py: merges both into one evidence report
to step4_llm_analysis.py: Gemini reads the evidence, returns a structured verdict

## Tech stack

- Python 3.12
- google-genai (Gemini API) for verdict synthesis
- BeautifulSoup4 for HTML parsing
- Built-in email and difflib libraries for parsing and typosquat similarity scoring

## Running it locally

pip install -r requirements.txt
$env:GEMINI_API_KEY = "your-key-here"
python step4_llm_analysis.py

## Status

Core pipeline (parsing, domain checks, LLM verdict) is complete and tested against sample phishing emails. A formal precision/recall benchmark against a labeled dataset is planned next.

## Author

Khan Rubayet Islam, Computer Science (Cybersecurity) student, Taylor's University
