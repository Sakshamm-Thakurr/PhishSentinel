import email
import email.policy
from bs4 import BeautifulSoup
import re


def parse_eml(file_path):
    """
    Takes a path to a .eml file.
    Returns a clean dictionary with headers, body text, and URLs.
    """
    with open(file_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)

    result = {
        "subject":      msg.get("Subject", ""),
        "from":         msg.get("From", ""),
        "to":           msg.get("To", ""),
        "reply_to":     msg.get("Reply-To", ""),
        "return_path":  msg.get("Return-Path", ""),
        "date":         msg.get("Date", ""),
        "message_id":   msg.get("Message-ID", ""),
        "received":     msg.get_all("Received", []),
        "spf":          msg.get("Received-SPF", ""),
        "dkim":         msg.get("DKIM-Signature", ""),
        "dmarc":        msg.get("Authentication-Results", ""),
        "body_text":    "",
        "body_html":    "",
        "urls":         []
    }

    # Extract body — handle both plain text and HTML emails
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                result["body_text"] += part.get_content()
            elif content_type == "text/html":
                result["body_html"] += part.get_content()
    else:
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            result["body_text"] = msg.get_content()
        elif content_type == "text/html":
            result["body_html"] = msg.get_content()

    # Extract URLs from both plain text and HTML
    result["urls"] = extract_urls(result["body_text"], result["body_html"])

    return result


def extract_urls(text, html):
    """
    Pulls all URLs from plain text body and HTML body combined.
    Deduplicates and returns a clean list.
    """
    urls = set()

    # Regex for plain text URLs
    url_pattern = re.compile(r'https?://[^\s<>"\']+')
    urls.update(url_pattern.findall(text))

    # Parse HTML and extract href links
    if html:
        soup = BeautifulSoup(html, "html.parser")
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith("http"):
                urls.add(href)

    return list(urls)