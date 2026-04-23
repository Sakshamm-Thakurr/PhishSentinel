import re


# ── Phishing keyword categories with weights ──────────────────

URGENCY_PHRASES = [
    "urgent", "immediately", "act now", "within 24 hours", "within 48 hours",
    "account suspended", "account locked", "account will be closed",
    "limited time", "expires soon", "last chance", "final notice",
    "your account has been", "unusual activity", "suspicious activity",
    "verify now", "confirm now", "update now", "respond immediately",
    "failure to respond", "legal action", "will be terminated"
]

CREDENTIAL_PHRASES = [
    "enter your password", "confirm your password", "verify your identity",
    "enter your details", "update your information", "login to verify",
    "click here to verify", "validate your account", "reactivate your account",
    "provide your", "submit your", "enter your credit card",
    "enter your social security", "banking details", "payment information"
]

IMPERSONATION_PHRASES = [
    "dear customer", "dear user", "dear account holder", "dear member",
    "dear valued customer", "hello user", "greetings from",
    "official notice", "security team", "support team",
    "helpdesk", "no-reply", "do not reply"
]

REWARD_PHRASES = [
    "you have won", "congratulations", "you are selected",
    "free gift", "claim your prize", "lucky winner",
    "cash reward", "bonus offer", "exclusive offer",
    "you have been chosen", "special offer just for you"
]

THREAT_PHRASES = [
    "your account will be deleted", "permanent suspension",
    "legal proceedings", "report to authorities",
    "criminal complaint", "your ip has been logged",
    "you have been hacked", "unauthorized access detected"
]

# Score each category hits
CATEGORY_SCORES = {
    "urgency":        3,
    "credential":     4,
    "impersonation":  2,
    "reward":         3,
    "threat":         4,
}


def score_body(parsed_email):
    """
    Analyzes email body text for phishing language patterns.
    Returns score, matched phrases, and risk flags.
    """
    # Combine plain text and stripped HTML text for analysis
    body = _get_analysis_text(parsed_email)

    results = {
        "risk_score":   0,
        "risk_flags":   [],
        "matched":      {},
        "body_length":  len(body),
        "checks":       []
    }

    if not body.strip():
        results["checks"].append({
            "code": "EMPTY_BODY",
            "status": "FLAG",
            "message": "Email body is empty — possible evasion technique."
        })
        results["risk_score"] += 10
        return results

    body_lower = body.lower()

    # Run each category
    _check_category(body_lower, "urgency",       URGENCY_PHRASES,       results)
    _check_category(body_lower, "credential",    CREDENTIAL_PHRASES,    results)
    _check_category(body_lower, "impersonation", IMPERSONATION_PHRASES, results)
    _check_category(body_lower, "reward",        REWARD_PHRASES,        results)
    _check_category(body_lower, "threat",        THREAT_PHRASES,        results)

    # Extra checks
    _check_excessive_caps(body, results)
    _check_mismatched_link_text(parsed_email, results)

    return results


def _check_category(body_lower, category, phrases, results):
    hits = [p for p in phrases if p in body_lower]
    if hits:
        score = CATEGORY_SCORES[category] * len(hits)
        results["risk_score"]     += score
        results["matched"][category] = hits
        results["risk_flags"].append({
            "code":    f"NLP_{category.upper()}",
            "message": f"{len(hits)} {category} phrase(s) detected: {', '.join(hits[:3])}{'...' if len(hits) > 3 else ''}",
            "score":   score
        })
        results["checks"].append({
            "code":    f"NLP_{category.upper()}",
            "status":  "FLAG",
            "message": f"{len(hits)} {category} phrase(s) found."
        })
    else:
        results["checks"].append({
            "code":   f"NLP_{category.upper()}",
            "status": "PASS",
            "message": f"No {category} phrases detected."
        })


def _check_excessive_caps(body, results):
    """Flags emails with too many ALL CAPS words — common in phishing."""
    words      = body.split()
    if not words:
        return
    caps_words = [w for w in words if w.isupper() and len(w) > 2]
    ratio      = len(caps_words) / len(words)

    if ratio > 0.2:
        score = 10
        results["risk_score"] += score
        results["risk_flags"].append({
            "code":    "EXCESSIVE_CAPS",
            "message": f"{int(ratio*100)}% of words are ALL CAPS — common phishing tactic.",
            "score":   score
        })
    else:
        results["checks"].append({
            "code":   "CAPS_NORMAL",
            "status": "PASS",
            "message": "Capitalization pattern is normal."
        })


def _check_mismatched_link_text(parsed_email, results):
    """
    Checks if visible link text says one domain
    but the actual href points somewhere different.
    Classic phishing trick.
    """
    from bs4 import BeautifulSoup
    html = parsed_email.get("body_html", "")
    if not html:
        return

    soup = BeautifulSoup(html, "html.parser")
    for tag in soup.find_all("a", href=True):
        href      = tag["href"].lower()
        link_text = tag.get_text().lower().strip()

        # If link text looks like a URL and doesn't match href domain
        if "." in link_text and "http" not in link_text:
            href_domain = _extract_domain(href)
            text_domain = _extract_domain("http://" + link_text)
            if href_domain and text_domain and href_domain != text_domain:
                score = 20
                results["risk_score"] += score
                results["risk_flags"].append({
                    "code":    "LINK_TEXT_MISMATCH",
                    "message": f"Link text shows '{link_text}' but href points to '{href_domain}' — hidden redirect.",
                    "score":   score
                })


def _extract_domain(url):
    match = re.search(r'https?://([^/]+)', url)
    return match.group(1).lower() if match else ""


def _get_analysis_text(parsed_email):
    """Returns best available text for NLP analysis."""
    if parsed_email.get("body_text"):
        return parsed_email["body_text"]

    # Strip HTML tags if only HTML body available
    from bs4 import BeautifulSoup
    html = parsed_email.get("body_html", "")
    if html:
        return BeautifulSoup(html, "html.parser").get_text(separator=" ")

    return ""