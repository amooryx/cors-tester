#!/usr/bin/env python3
"""
CORS Misconfiguration Tester - by amooryx
Systematically tests CORS policies for misconfigurations and bypass techniques.
"""

import sys
import json
import argparse
import time
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[!] Missing dep: pip install requests")
    sys.exit(1)

BANNER = r"""
   ______  ____  ____  _____   ______          __           
  / ____/ / __ \/ __ \/ ___/  /_  __/__  _____/ /____  _____
 / /     / / / / /_/ /\__ \    / / / _ \/ ___/ __/ _ \/ ___/
/ /___  / /_/ / _, _/___/ /   / / /  __(__  ) /_/  __/ /    
\____/  \____/_/ |_|/____/   /_/  \___/____/\__/\___/_/     

  CORS Misconfiguration Tester v1.0 | by amooryx
"""

# ─────────────────────────────────────────────
#  Data models
# ─────────────────────────────────────────────

@dataclass
class CorsResult:
    test_name: str
    origin_sent: str
    acao: Optional[str]          # Access-Control-Allow-Origin
    acac: Optional[str]          # Access-Control-Allow-Credentials
    acam: Optional[str]          # Access-Control-Allow-Methods
    acah: Optional[str]          # Access-Control-Allow-Headers
    status_code: int
    vulnerable: bool
    severity: str                # critical / high / medium / low / info
    detail: str
    preflight_status: Optional[int] = None


# ─────────────────────────────────────────────
#  HTTP helper
# ─────────────────────────────────────────────

def send_cors_request(
    url: str,
    origin: str,
    extra_headers: Dict[str, str],
    method: str = "GET",
    timeout: int = 10,
    proxy: Optional[str] = None,
    cookies: Optional[str] = None,
) -> Tuple[Optional[requests.Response], Optional[requests.Response]]:
    """Send CORS request and optional preflight. Returns (main_response, preflight_response)."""
    headers = {"Origin": origin, **extra_headers}
    if cookies:
        headers["Cookie"] = cookies

    proxies = {"http": proxy, "https": proxy} if proxy else None

    preflight_resp = None
    try:
        # Preflight
        pf_headers = {
            "Origin": origin,
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "Authorization",
        }
        preflight_resp = requests.options(
            url, headers=pf_headers, proxies=proxies,
            verify=False, timeout=timeout, allow_redirects=False
        )
    except Exception:
        pass

    try:
        resp = requests.request(
            method, url, headers=headers, proxies=proxies,
            verify=False, timeout=timeout, allow_redirects=True
        )
        return resp, preflight_resp
    except requests.exceptions.RequestException as e:
        print(f"  [!] Request error: {e}")
        return None, None


def extract_cors_headers(resp: requests.Response) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    acao = resp.headers.get("Access-Control-Allow-Origin")
    acac = resp.headers.get("Access-Control-Allow-Credentials")
    acam = resp.headers.get("Access-Control-Allow-Methods")
    acah = resp.headers.get("Access-Control-Allow-Headers")
    return acao, acac, acam, acah


# ─────────────────────────────────────────────
#  Test Cases
# ─────────────────────────────────────────────

def test_wildcard(url: str, headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> CorsResult:
    """Test 1: Simple wildcard"""
    origin = "https://evil.com"
    resp, _ = send_cors_request(url, origin, headers, timeout=timeout, proxy=proxy, cookies=cookies)
    if not resp:
        return CorsResult("Wildcard ACAO", origin, None, None, None, None, 0, False, "info", "Request failed")

    acao, acac, acam, acah = extract_cors_headers(resp)
    vulnerable = acao == "*"
    severity = "medium" if vulnerable and acac != "true" else "low"
    detail = "Wildcard ACAO (*) reflects all origins." if vulnerable else "Not vulnerable."

    return CorsResult("Wildcard ACAO", origin, acao, acac, acam, acah,
                      resp.status_code, vulnerable, severity, detail)


def test_origin_reflection(url: str, headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> CorsResult:
    """Test 2: Arbitrary origin reflection"""
    origin = "https://evil.com"
    resp, _ = send_cors_request(url, origin, headers, timeout=timeout, proxy=proxy, cookies=cookies)
    if not resp:
        return CorsResult("Origin Reflection", origin, None, None, None, None, 0, False, "info", "Request failed")

    acao, acac, acam, acah = extract_cors_headers(resp)
    reflected = acao == origin
    creds_allowed = acac and acac.lower() == "true"
    vulnerable = reflected and creds_allowed
    severity = "critical" if vulnerable else ("high" if reflected else "info")
    detail = (
        "CRITICAL: Arbitrary origin reflected WITH credentials! Full exploitation possible."
        if vulnerable else
        "Origin reflected but credentials not allowed — limited impact."
        if reflected else
        "Origin not reflected."
    )

    return CorsResult("Origin Reflection + Credentials", origin, acao, acac, acam, acah,
                      resp.status_code, vulnerable, severity, detail)


def test_null_origin(url: str, headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> CorsResult:
    """Test 3: null origin"""
    origin = "null"
    resp, _ = send_cors_request(url, origin, headers, timeout=timeout, proxy=proxy, cookies=cookies)
    if not resp:
        return CorsResult("Null Origin", origin, None, None, None, None, 0, False, "info", "Request failed")

    acao, acac, acam, acah = extract_cors_headers(resp)
    reflected = acao == "null"
    creds_allowed = acac and acac.lower() == "true"
    vulnerable = reflected
    severity = "high" if reflected and creds_allowed else ("medium" if reflected else "info")
    detail = (
        "null origin accepted with credentials! Exploitable via sandboxed iframe."
        if reflected and creds_allowed else
        "null origin accepted (no credentials) — limited risk."
        if reflected else
        "null origin rejected."
    )

    return CorsResult("Null Origin", origin, acao, acac, acam, acah,
                      resp.status_code, vulnerable, severity, detail)


def test_subdomain_bypass(url: str, headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> List[CorsResult]:
    """Test 4: Trusted subdomain bypass"""
    parsed = urlparse(url)
    base_domain = parsed.netloc

    # Strip port if present
    if ":" in base_domain:
        base_domain = base_domain.split(":")[0]

    test_origins = [
        f"https://evil.{base_domain}",
        f"https://attacker.{base_domain}",
        f"https://notreally{base_domain}",
        f"https://evil.com.{base_domain}",
    ]

    results = []
    for origin in test_origins:
        resp, _ = send_cors_request(url, origin, headers, timeout=timeout, proxy=proxy, cookies=cookies)
        if not resp:
            continue
        acao, acac, acam, acah = extract_cors_headers(resp)
        reflected = acao == origin
        creds_allowed = acac and acac.lower() == "true"
        vulnerable = reflected
        severity = "critical" if reflected and creds_allowed else ("high" if reflected else "info")
        detail = (
            f"Subdomain '{origin}' accepted with credentials! Subdomain takeover → full exploit."
            if reflected and creds_allowed else
            f"Subdomain '{origin}' accepted without credentials."
            if reflected else
            f"Subdomain '{origin}' rejected."
        )
        results.append(CorsResult(
            f"Subdomain Bypass ({origin})", origin, acao, acac, acam, acah,
            resp.status_code, vulnerable, severity, detail
        ))
    return results


def test_prefix_bypass(url: str, headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> CorsResult:
    """Test 5: Domain prefix bypass (e.g. target.com.evil.com)"""
    parsed = urlparse(url)
    base = parsed.netloc.split(":")[0]
    origin = f"https://{base}.evil.com"

    resp, _ = send_cors_request(url, origin, headers, timeout=timeout, proxy=proxy, cookies=cookies)
    if not resp:
        return CorsResult("Prefix Bypass", origin, None, None, None, None, 0, False, "info", "Request failed")

    acao, acac, acam, acah = extract_cors_headers(resp)
    reflected = acao == origin
    creds_allowed = acac and acac.lower() == "true"
    vulnerable = reflected
    severity = "critical" if reflected and creds_allowed else ("high" if reflected else "info")
    detail = (
        f"Prefix bypass works! '{origin}' accepted — regex only checks startsWith."
        if reflected else
        "Prefix bypass rejected."
    )

    return CorsResult("Prefix Bypass", origin, acao, acac, acam, acah,
                      resp.status_code, vulnerable, severity, detail)


def test_http_origin(url: str, headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> CorsResult:
    """Test 6: HTTP downgrade (http:// instead of https://)"""
    parsed = urlparse(url)
    base = parsed.netloc.split(":")[0]
    origin = f"http://{base}"

    resp, _ = send_cors_request(url, origin, headers, timeout=timeout, proxy=proxy, cookies=cookies)
    if not resp:
        return CorsResult("HTTP Origin Downgrade", origin, None, None, None, None, 0, False, "info", "Request failed")

    acao, acac, acam, acah = extract_cors_headers(resp)
    reflected = acao == origin
    vulnerable = reflected
    severity = "medium" if reflected else "info"
    detail = (
        "HTTP origin accepted — enables MITM attack on HTTP to extract CORS responses."
        if reflected else
        "HTTP origin rejected."
    )

    return CorsResult("HTTP Origin Downgrade", origin, acao, acac, acam, acah,
                      resp.status_code, vulnerable, severity, detail)


def test_preflight_bypass(url: str, headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> CorsResult:
    """Test 7: Missing/weak preflight validation"""
    origin = "https://evil.com"
    resp, preflight = send_cors_request(url, origin, headers, timeout=timeout, proxy=proxy, cookies=cookies)
    if not resp or not preflight:
        return CorsResult("Preflight Bypass", origin, None, None, None, None, 0, False, "info", "Request/preflight failed")

    acao, acac, acam, acah = extract_cors_headers(preflight)
    pf_status = preflight.status_code
    no_preflight_enforcement = pf_status not in [200, 204] or not acao
    severity = "low" if no_preflight_enforcement else "info"
    detail = (
        f"Preflight returned {pf_status} with no CORS headers — server may not enforce preflight properly."
        if no_preflight_enforcement else
        f"Preflight properly handled (HTTP {pf_status})."
    )

    return CorsResult("Preflight Validation", origin, acao, acac, acam, acah,
                      resp.status_code, no_preflight_enforcement, severity, detail,
                      preflight_status=pf_status)


# ─────────────────────────────────────────────
#  Runner & Report
# ─────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_COLOR = {
    "critical": "🔴 CRITICAL",
    "high":     "🟠 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🟢 LOW",
    "info":     "⚪ INFO",
}


def run_all_tests(url: str, extra_headers: Dict, timeout: int, proxy: Optional[str], cookies: Optional[str]) -> List[CorsResult]:
    print(f"\n  Target: {url}")
    print(f"  {'─'*60}")

    results = []
    results.append(test_wildcard(url, extra_headers, timeout, proxy, cookies))
    results.append(test_origin_reflection(url, extra_headers, timeout, proxy, cookies))
    results.append(test_null_origin(url, extra_headers, timeout, proxy, cookies))
    results.extend(test_subdomain_bypass(url, extra_headers, timeout, proxy, cookies))
    results.append(test_prefix_bypass(url, extra_headers, timeout, proxy, cookies))
    results.append(test_http_origin(url, extra_headers, timeout, proxy, cookies))
    results.append(test_preflight_bypass(url, extra_headers, timeout, proxy, cookies))

    return results


def print_results(results: List[CorsResult]):
    print(f"\n  {'─'*70}")
    print(f"  {'Test':<40} {'Severity':<18} {'ACAO':<30}")
    print(f"  {'─'*38} {'─'*16} {'─'*28}")

    for r in sorted(results, key=lambda x: SEVERITY_ORDER.get(x.severity, 5)):
        sev_label = SEVERITY_COLOR.get(r.severity, r.severity.upper())
        acao_val = (r.acao or "-")[:28]
        print(f"  {r.test_name:<40} {sev_label:<18} {acao_val}")

    print(f"\n  {'─'*70}")
    print("  DETAILS:")
    for r in results:
        if r.vulnerable or r.severity in ["critical", "high", "medium"]:
            print(f"\n  [{r.severity.upper()}] {r.test_name}")
            print(f"    Origin sent : {r.origin_sent}")
            print(f"    ACAO        : {r.acao or 'not set'}")
            print(f"    ACAC        : {r.acac or 'not set'}")
            print(f"    Detail      : {r.detail}")


def save_json(results: List[CorsResult], url: str, path: str):
    data = {
        "target": url,
        "timestamp": datetime.utcnow().isoformat(),
        "total": len(results),
        "vulnerable": sum(1 for r in results if r.vulnerable),
        "findings": [
            {
                "test": r.test_name,
                "origin_sent": r.origin_sent,
                "acao": r.acao,
                "acac": r.acac,
                "status": r.status_code,
                "vulnerable": r.vulnerable,
                "severity": r.severity,
                "detail": r.detail,
            }
            for r in results
        ]
    }
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n  [+] JSON report saved: {path}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

def parse_headers(raw: List[str]) -> Dict[str, str]:
    result = {}
    for item in raw or []:
        if ":" in item:
            k, v = item.split(":", 1)
            result[k.strip()] = v.strip()
    return result


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="CORS Misconfiguration Tester — systematic CORS policy analysis",
        formatter_class=argparse.RawTextHelpFormatter
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-u", "--url", help="Single target URL")
    group.add_argument("-l", "--list", help="File with URLs to test (one per line)")

    parser.add_argument("-H", "--header", action="append", metavar="Key:Value",
                        help="Custom headers: -H 'Authorization: Bearer token'")
    parser.add_argument("--cookies", help="Cookie string to include")
    parser.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout per request (default: 10)")
    parser.add_argument("--json", help="Save results to JSON file")

    args = parser.parse_args()

    extra_headers = parse_headers(args.header)

    urls = []
    if args.url:
        urls = [args.url]
    elif args.list:
        try:
            with open(args.list) as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[!] List not found: {args.list}")
            sys.exit(1)

    all_results = {}
    for url in urls:
        results = run_all_tests(url, extra_headers, args.timeout, args.proxy, args.cookies)
        print_results(results)
        all_results[url] = results

    if args.json and len(urls) == 1:
        save_json(all_results[urls[0]], urls[0], args.json)
    elif args.json:
        combined = []
        for url, results in all_results.items():
            for r in results:
                combined.append({**r.__dict__, "url": url})
        with open(args.json, "w") as f:
            json.dump(combined, f, indent=2)
        print(f"\n[+] JSON report saved: {args.json}")

    print("\n[*] Done.")


if __name__ == "__main__":
    main()
