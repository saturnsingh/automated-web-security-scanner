# Automated Web Security Scanner

A small educational Python utility that makes a single HTTP GET request to a URL the user is authorized to assess, checks a set of common HTTP security headers, and records the results in a JSON report.

## Project overview

This project is designed for learning and classroom review. It does not crawl websites, exploit vulnerabilities, or certify that a target is secure. It only inspects selected response headers from one requested URL.

The scanner checks the following headers:
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Access-Control-Allow-Origin
- Access-Control-Allow-Credentials

## Features
- Validates that the target URL uses http:// or https://
- Confirms user authorization before sending a request
- Sends a single GET request with a 10-second timeout
- Saves the result to security_scan_report.json
- Reports missing headers without labeling them as automatic vulnerabilities
- Documents limitations and safe-use guidance

## Prerequisites
- Python 3.10 or later
- Internet access to the authorized target
- Permission to test the target URL

## Installation

Clone or download the repository and open a terminal in the project folder.

```bash
python -m pip install -r requirements.txt
```

## Run the scanner

```bash
python SatyamSingh_AutomatedWebSecurityScanner.py
```

Example:

```bash
Enter a URL you are authorized to test (http:// or https://): https://example.com
```

After entering a URL, the program will ask for confirmation:

```text
Do you have authorization to scan this target? Type YES:
```

If you type YES, the script sends one HTTP request and prints a summary.

## Expected behavior

The script prints a report similar to:

```text
[AUTOMATED WEB SECURITY SCANNER — RESULTS]
Target: https://example.com
HTTP status: 200
SECURITY HEADERS
[PRESENT] Content-Security-Policy
[MISSING] Strict-Transport-Security
...
SUMMARY: {'headers_checked': 6, 'headers_present': 3, 'headers_missing': 3, 'request_succeeded': True}
```

The JSON report is written to:

```text
security_scan_report.json
```

## Safe and authorized use

- Only scan systems you own or have explicit written authorization to test.
- Do not use the results as proof that a site is secure or vulnerable.
- Do not disable TLS certificate verification.
- Do not scan production or sensitive systems without permission.
- This project is educational; it is not a vulnerability scanner or penetration-testing tool.

## Limitations

- It checks a single URL, not a full site crawl.
- It does not validate whether each header value is appropriate for the application.
- It does not test authenticated pages or application-specific CORS behavior.
- Missing headers are not automatically vulnerabilities.

## Running tests

The repository includes automated tests for valid and invalid URLs, timeouts, connection failures, and missing headers.

```bash
python -m pytest -q
```

## Repository status

The project report file `SatyamSingh_ProjectReport.docx` is not present in this repository snapshot. It should be created separately if required by your course or instructor.
