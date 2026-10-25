# Automated Web Security Scanner

## Project description
This beginner-friendly Python project makes one HTTP GET request to a URL that the user is authorized to assess, checks selected HTTP security response headers, reviews two CORS response headers, and saves findings to `security_scan_report.json`.

It checks:
- Content-Security-Policy
- Strict-Transport-Security
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Access-Control-Allow-Origin and Access-Control-Allow-Credentials (context review only)

**Important:** Missing headers are not automatically vulnerabilities. Header presence does not prove that a header is configured correctly. This tool is not a penetration-testing tool and does not crawl or exploit a site.

## Technologies used
- Python 3
- Requests
- JSON
- Python standard library (`urllib.parse`, `datetime`)

## Dataset
This project does not require a dataset; it analyses HTTP response headers returned by the authorized test target. For a reproducible classroom demonstration, use a local test server you control and document the test responses. Do not claim that a public dataset was used.

## Files
- `SatyamSingh_AutomatedWebSecurityScanner.py` — source code
- `requirements.txt` — Python dependency
- `SatyamSingh_ProjectReport.docx` — project report

## Setup and run
1. Install Python 3.10 or later.
2. Save the source file to a folder.
3. Install the dependency:
   ```bash
   python -m pip install -r requirements.txt
   ```
4. Run:
   ```bash
   python SatyamSingh_AutomatedWebSecurityScanner.py
   ```
5. Enter a complete `http://` or `https://` URL only if you own the target or have explicit permission.
6. Type `YES` when asked to confirm authorization.
7. Review the terminal output and the generated `security_scan_report.json`.

### Android / Pydroid 3
Install Pydroid 3 and the `requests` package in its Pip interface. Open the `.py` file and run it. The JSON report is saved to the script's working directory; check Pydroid's file browser if you cannot locate it.

## Ethical and safe use
- Scan only systems you own or have explicit permission to test.
- The program sends a single GET request and follows redirects.
- Do not use results as proof of a vulnerability or proof that a site is secure.
- Do not disable TLS certificate verification.
- Avoid scanning sensitive or production systems without written authorization.

## Limitations and future improvements
- It only checks response headers from one requested URL.
- It does not validate the quality of each header's policy.
- It does not test authenticated pages or application-specific CORS behaviour.
- Future work could include HTML/JSON export, unit tests, a local mock server, and severity guidance reviewed by a security instructor.

## Author
The report identifies the student as Satyam Singh. Add class, college, and submission date if required by the organizer.
