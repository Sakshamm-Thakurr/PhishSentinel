import re
import requests
import base64
import time
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE    = "https://www.virustotal.com/api/v3/urls"


def analyze_urls(parsed_email):
    """
    Takes parsed email dict.
    For each URL found, queries VirusTotal and returns
    a reputation result with malicious/suspicious counts.
    """
    urls = parsed_email.get("urls", [])

    results = {
        "urls_found": len(urls),
        "risk_score": 0,
        "url_results": [],
        "risk_flags": []
    }

    if not urls:
        results["risk_flags"].append({
            "code": "NO_URLS",
            "message": "No URLs found in email body.",
            "score": 0
        })
        return results

    for url in urls:
        print(f"  Checking URL: {url}")
        vt_result = _query_virustotal(url)
        results["url_results"].append(vt_result)

        # Score based on how many engines flagged it
        malicious   = vt_result.get("malicious", 0)
        suspicious  = vt_result.get("suspicious", 0)

        if malicious >= 5:
            score = 50
            results["risk_flags"].append({
                "code": "URL_MALICIOUS",
                "message": f"{url} flagged malicious by {malicious} AV engines on VirusTotal.",
                "score": score
            })
            results["risk_score"] += score

        elif malicious >= 1 or suspicious >= 3:
            score = 25
            results["risk_flags"].append({
                "code": "URL_SUSPICIOUS",
                "message": f"{url} flagged suspicious — {malicious} malicious, {suspicious} suspicious engines.",
                "score": score
            })
            results["risk_score"] += score

        else:
            results["url_results"][-1]["verdict"] = "CLEAN"

        # VirusTotal free tier = 4 requests/minute
        time.sleep(16)

    return results


def _query_virustotal(url):
    """
    Submits a URL to VirusTotal and returns the analysis summary.
    Uses base64 URL ID as per VT API v3 spec.
    """
    headers = {"x-apikey": VT_API_KEY}

    # VT API v3 requires URL encoded as base64 (no padding)
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    try:
        # First try to GET existing analysis
        response = requests.get(
            f"{VT_BASE}/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code == 200:
            return _parse_vt_response(url, response.json())

        # If not found, submit it for scanning
        elif response.status_code == 404:
            post_resp = requests.post(
                VT_BASE,
                headers=headers,
                data={"url": url},
                timeout=10
            )
            if post_resp.status_code == 200:
                # Wait for analysis then fetch
                time.sleep(10)
                get_resp = requests.get(
                    f"{VT_BASE}/{url_id}",
                    headers=headers,
                    timeout=10
                )
                if get_resp.status_code == 200:
                    return _parse_vt_response(url, get_resp.json())

        return _error_result(url, f"HTTP {response.status_code}")

    except requests.exceptions.RequestException as e:
        return _error_result(url, str(e))


def _parse_vt_response(url, data):
    """Pulls the stats we care about from VT response."""
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "url":        url,
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "verdict":    "MALICIOUS" if stats.get("malicious", 0) >= 1 else "CLEAN"
        }
    except KeyError:
        return _error_result(url, "Unexpected VT response format")


def _error_result(url, reason):
    return {
        "url":       url,
        "malicious": 0,
        "suspicious": 0,
        "harmless":  0,
        "undetected": 0,
        "verdict":   "ERROR",
        "error":     reason
    }