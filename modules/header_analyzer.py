import re
from email.utils import parseaddr


def analyze_headers(parsed_email):
    """
    Takes the parsed email dictionary from email_parser.py
    Analyzes headers for spoofing, authentication failures, and anomalies.
    Returns a findings dictionary with a risk score.
    """

    findings = {
        "checks": [],
        "risk_score": 0,       # will increase with each red flag
        "risk_flags": []       # human-readable list of what's suspicious
    }

    _check_spf(parsed_email, findings)
    _check_dkim(parsed_email, findings)
    _check_dmarc(parsed_email, findings)
    _check_reply_to_mismatch(parsed_email, findings)
    _check_return_path_mismatch(parsed_email, findings)
    _check_domain_spoofing(parsed_email, findings)
    _check_received_chain(parsed_email, findings)

    return findings


# ── individual checks ──────────────────────────────────────────


def _check_spf(parsed_email, findings):
    spf = parsed_email.get("spf", "").lower()
    if "fail" in spf:
        _add_flag(findings, "SPF_FAIL",
                  "SPF check failed — sender IP not authorised to send for this domain.", 30)
    elif "softfail" in spf:
        _add_flag(findings, "SPF_SOFTFAIL",
                  "SPF softfail — sender IP is suspicious but not hard-blocked.", 15)
    elif "pass" in spf:
        _add_check(findings, "SPF_PASS", "SPF passed.")
    else:
        _add_flag(findings, "SPF_MISSING",
                  "No SPF record found — domain has no sender policy.", 10)


def _check_dkim(parsed_email, findings):
    dkim = parsed_email.get("dkim", "").strip()
    if not dkim:
        _add_flag(findings, "DKIM_MISSING",
                  "No DKIM signature found — email integrity cannot be verified.", 20)
    else:
        _add_check(findings, "DKIM_PRESENT", "DKIM signature present.")


def _check_dmarc(parsed_email, findings):
    dmarc = parsed_email.get("dmarc", "").lower()
    if not dmarc:
        _add_flag(findings, "DMARC_MISSING",
                  "No DMARC authentication results found.", 10)
    elif "dmarc=fail" in dmarc:
        _add_flag(findings, "DMARC_FAIL",
                  "DMARC check failed — email does not align with domain policy.", 25)
    elif "dmarc=pass" in dmarc:
        _add_check(findings, "DMARC_PASS", "DMARC passed.")


def _check_reply_to_mismatch(parsed_email, findings):
    from_addr  = parseaddr(parsed_email.get("from", ""))[1].lower()
    reply_addr = parseaddr(parsed_email.get("reply_to", ""))[1].lower()

    if reply_addr and reply_addr != from_addr:
        from_domain  = from_addr.split("@")[-1]  if "@" in from_addr  else ""
        reply_domain = reply_addr.split("@")[-1] if "@" in reply_addr else ""
        if from_domain != reply_domain:
            _add_flag(findings, "REPLY_TO_MISMATCH",
                      f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — classic BEC/phishing indicator.", 35)


def _check_return_path_mismatch(parsed_email, findings):
    from_addr   = parseaddr(parsed_email.get("from", ""))[1].lower()
    return_path = parseaddr(parsed_email.get("return_path", ""))[1].lower()

    if return_path and return_path != from_addr:
        from_domain   = from_addr.split("@")[-1]   if "@" in from_addr   else ""
        return_domain = return_path.split("@")[-1] if "@" in return_path else ""
        if from_domain != return_domain:
            _add_flag(findings, "RETURN_PATH_MISMATCH",
                      f"Return-Path domain ({return_domain}) differs from From domain ({from_domain}).", 20)


def _check_domain_spoofing(parsed_email, findings):
    """
    Checks if the From display name mentions a trusted brand
    but the actual email domain doesn't match.
    """
    trusted_brands = {
        "paypal":    "paypal.com",
        "google":    "google.com",
        "microsoft": "microsoft.com",
        "apple":     "apple.com",
        "amazon":    "amazon.com",
        "netflix":   "netflix.com",
        "facebook":  "facebook.com",
        "instagram": "instagram.com",
        "linkedin":  "linkedin.com",
        "twitter":   "twitter.com",
        "infosys":   "infosys.com",
        "hdfc":      "hdfcbank.com",
        "sbi":       "sbi.co.in",
    }

    from_full  = parsed_email.get("from", "").lower()
    from_addr  = parseaddr(from_full)[1].lower()
    from_domain = from_addr.split("@")[-1] if "@" in from_addr else ""

    for brand, legit_domain in trusted_brands.items():
        if brand in from_full and legit_domain not in from_domain:
            _add_flag(findings, "BRAND_SPOOFING",
                      f"Email claims to be from '{brand}' but sending domain is '{from_domain}' not '{legit_domain}'.", 40)
            break


def _check_received_chain(parsed_email, findings):
    """
    Checks the Received headers chain for anomalies —
    a long or inconsistent chain can indicate relaying through
    suspicious servers.
    """
    received = parsed_email.get("received", [])
    if len(received) > 7:
        _add_flag(findings, "LONG_RECEIVED_CHAIN",
                  f"Unusually long Received chain ({len(received)} hops) — may indicate relay abuse.", 10)
    else:
        _add_check(findings, "RECEIVED_CHAIN_NORMAL",
                   f"Received chain length is normal ({len(received)} hops).")


# ── helpers ────────────────────────────────────────────────────


def _add_flag(findings, code, message, score):
    findings["risk_score"] += score
    findings["risk_flags"].append({"code": code, "message": message, "score": score})
    findings["checks"].append({"code": code, "status": "FLAG", "message": message})


def _add_check(findings, code, message):
    findings["checks"].append({"code": code, "status": "PASS", "message": message})