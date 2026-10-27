
import sys
import requests
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce injection attacks",
    "Strict-Transport-Security": "Enforces HTTPS",
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "X-Frame-Options": "Helps prevent clickjacking",
    "Referrer-Policy": "Controls referrer information",
    "Permissions-Policy": "Controls browser features"
}


def scan_website(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print("[ERROR] Enter a valid HTTP or HTTPS URL.")
        return

    if parsed.username or parsed.password:
        print("[ERROR] URLs containing credentials are not allowed.")
        return

    print("\n========================================")
    print("      AUTOMATED WEB SECURITY SCANNER")
    print("========================================")
    print("Target:", url)

    if parsed.scheme != "https":
        print("[WARN] Website is not using HTTPS.")

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "EducationalSecurityScanner/1.0"}
        )
    except requests.RequestException as error:
        print("[ERROR] Request failed:", error)
        return

    print("Final URL:", response.url)
    print("HTTP Status:", response.status_code)

    findings = 0
    passed = 0

    print("\n--- SECURITY HEADERS ---")

    for header, description in SECURITY_HEADERS.items():
        if header in response.headers:
            print("[PASS]", header)
            passed += 1
        else:
            print("[WARN]", header, "is missing")
            findings += 1

    print("\n--- COOKIE SECURITY ---")

    cookies = response.raw.headers.getlist("Set-Cookie")

    if not cookies:
        print("[INFO] No cookies returned.")
    else:
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            parts = [
                part.strip().lower()
                for part in cookie.split(";")
            ]

            missing = []

            if "secure" not in parts:
                missing.append("Secure")

            if "httponly" not in parts:
                missing.append("HttpOnly")

            if not any(part.startswith("samesite=") for part in parts):
                missing.append("SameSite")

            if missing:
                print(
                    "[WARN]", name,
                    "missing:", ", ".join(missing)
                )
                findings += 1
            else:
                print("[PASS]", name, "has common security flags")
                passed += 1

    print("\n--- CORS CHECK ---")

    cors_origin = response.headers.get(
        "Access-Control-Allow-Origin"
    )

    if cors_origin == "*":
        print("[WARN] Wildcard CORS origin configured.")
        findings += 1
    elif cors_origin:
        print("[INFO] Allowed origin:", cors_origin)
    else:
        print("[INFO] No CORS allow-origin header returned.")

    print("\n--- FINAL REPORT ---")
    print("Checks passed:", passed)
    print("Potential findings:", findings)
    print("Scan completed.")
    print("This is a basic security configuration audit.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python scanner.py https://example.com")
    else:
        scan_website(sys.argv[1])
