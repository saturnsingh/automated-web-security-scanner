"""
Automated Web Security Scanner
Educational project for checking selected HTTP security headers.

Use only on systems you own or have explicit permission to assess.
This tool performs a single HTTP GET request and checks response headers.
It is not a penetration-testing tool and does not prove that a site is secure.
"""

import json
from datetime import datetime
from urllib.parse import urlparse

import requests


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Review whether a suitable Content Security Policy is needed. "
        "A policy should be designed and tested for the application."
    ),
    "Strict-Transport-Security": (
        "For HTTPS sites, review whether HTTP Strict Transport Security "
        "(HSTS) is appropriate and correctly configured."
    ),
    "X-Content-Type-Options": (
        "Consider X-Content-Type-Options: nosniff where appropriate."
    ),
    "X-Frame-Options": (
        "Review clickjacking protection. CSP frame-ancestors may also be used."
    ),
    "Referrer-Policy": (
        "Review whether a Referrer-Policy suitable for the application is needed."
    ),
    "Permissions-Policy": (
        "Review whether browser features should be restricted with Permissions-Policy."
    ),
}


def validate_url(url):
    """Return a parsed URL if it is a valid HTTP(S) URL; otherwise raise ValueError."""
    if not isinstance(url, str):
        raise ValueError("Enter a complete URL beginning with http:// or https://.")

    cleaned_url = url.strip()
    parsed = urlparse(cleaned_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a complete URL beginning with http:// or https://.")
    return parsed


def check_target_confirmation(hostname):
    """
    Ask for explicit authorization confirmation before making a request.
    This is a user-safety prompt, not technical proof of authorization.
    """
    print(f"\nTarget host: {hostname}")
    print("Only continue if you own this system or have explicit permission to test it.")
    try:
        confirmation = input("Do you have authorization to scan this target? Type YES: ").strip()
    except EOFError:
        print("No input received. Scan cancelled.")
        return False
    return confirmation == "YES"


def _format_request_error(exc):
    """Convert request exceptions into user-friendly, actionable messages."""
    if isinstance(exc, requests.exceptions.SSLError):
        return (
            "TLS/SSL error: the secure connection could not be established. "
            "Check the URL and certificate; do not disable certificate verification."
        )
    if isinstance(exc, requests.exceptions.Timeout):
        return "Request timed out after 10 seconds."
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Connection failed. Check the URL and network connection."
    if isinstance(exc, requests.exceptions.InvalidURL):
        return "Invalid URL. Enter a complete http:// or https:// address."
    return f"Request failed: {type(exc).__name__}: {exc}"


def scan_url(url):
    """Request a page and inspect selected response headers."""
    parsed = validate_url(url)
    result = {
        "project": "Automated Web Security Scanner",
        "target_url": url.strip(),
        "target_host": parsed.hostname,
        "scan_time": datetime.now().astimezone().isoformat(),
        "method": "GET",
        "scope": "Single HTTP request; response-header review only",
        "findings": [],
        "cors_review": {},
        "errors": [],
        "limitations": [
            "Missing headers are not automatically vulnerabilities.",
            "Header presence does not prove that the configuration is correct.",
            "This tool does not crawl pages, exploit vulnerabilities, or perform penetration testing.",
            "CORS risk depends on the full application context, including credentials and allowed resources.",
        ],
    }

    try:
        response = requests.get(
            url.strip(),
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Educational-Web-Security-Scanner/1.0"},
        )
    except requests.exceptions.RequestException as exc:
        result["errors"].append(_format_request_error(exc))
        result["summary"] = {
            "headers_checked": len(SECURITY_HEADERS),
            "headers_present": 0,
            "headers_missing": len(SECURITY_HEADERS),
            "request_succeeded": False,
        }
        return result

    result["http_status"] = response.status_code
    result["final_url"] = response.url
    result["redirect_count"] = len(response.history)

    headers = response.headers or {}
    for header, recommendation in SECURITY_HEADERS.items():
        value = headers.get(header)
        result["findings"].append({
            "header": header,
            "status": "Present" if value else "Missing",
            "value": value,
            "recommendation": recommendation if not value else (
                "Header is present. Review its value and application context."
            ),
        })

    allow_origin = headers.get("Access-Control-Allow-Origin")
    allow_credentials = headers.get("Access-Control-Allow-Credentials")
    result["cors_review"] = {
        "access_control_allow_origin": allow_origin,
        "access_control_allow_credentials": allow_credentials,
        "wildcard_origin_observed": bool(allow_origin and allow_origin.strip() == "*"),
        "note": (
            "A wildcard origin is not automatically a vulnerability. "
            "Review which resources are exposed and the full CORS configuration."
        ),
    }

    present = sum(item["status"] == "Present" for item in result["findings"])
    missing = sum(item["status"] == "Missing" for item in result["findings"])
    result["summary"] = {
        "headers_checked": len(result["findings"]),
        "headers_present": present,
        "headers_missing": missing,
        "request_succeeded": True,
    }
    return result


def print_report(result):
    """Display a readable summary in the terminal."""
    print("\n" + "=" * 58)
    print("AUTOMATED WEB SECURITY SCANNER — RESULTS")
    print("=" * 58)
    print("Target:", result["target_url"])
    print("Scan time:", result["scan_time"])
    if "http_status" in result:
        print("HTTP status:", result["http_status"])
        print("Final URL:", result.get("final_url"))
        print("Redirects:", result.get("redirect_count", 0))

    print("\nSECURITY HEADERS")
    print("-" * 58)
    for item in result["findings"]:
        print(f"[{item['status'].upper()}] {item['header']}")
        if item["value"]:
            print("  Value:", item["value"])
        else:
            print("  Recommendation:", item["recommendation"])

    cors = result["cors_review"]
    print("\nCORS REVIEW")
    print("-" * 58)
    print("Access-Control-Allow-Origin:", cors.get("access_control_allow_origin") or "Not present")
    print("Access-Control-Allow-Credentials:", cors.get("access_control_allow_credentials") or "Not present")
    if cors.get("wildcard_origin_observed"):
        print("Review note: wildcard origin observed; assess context.")

    if result["errors"]:
        print("\nERRORS")
        for error in result["errors"]:
            print("-", error)

    print("\nSUMMARY:", result["summary"])
    print("\nLimitations: this is a basic response-header checker, not a vulnerability verdict.")
    print("=" * 58)


def save_json_report(result, filename="security_scan_report.json"):
    """Save the scan results to a JSON file."""
    with open(filename, "w", encoding="utf-8") as report_file:
        json.dump(result, report_file, indent=2, ensure_ascii=False)
    return filename


def main():
    print("=" * 58)
    print("AUTOMATED WEB SECURITY SCANNER")
    print("Educational project: response-header configuration review")
    print("=" * 58)
    url = input("Enter a URL you are authorized to test (http:// or https://): ").strip()

    try:
        parsed = validate_url(url)
    except ValueError as exc:
        print("Invalid URL:", exc)
        return

    if not check_target_confirmation(parsed.hostname):
        print("Scan cancelled. Obtain permission before testing a system.")
        return

    result = scan_url(url)
    print_report(result)

    try:
        filename = save_json_report(result)
        print(f"\nJSON report saved to: {filename}")
    except OSError as exc:
        print("\nCould not save report:", exc)


if __name__ == "__main__":
    main()
