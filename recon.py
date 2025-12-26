#!/usr/bin/env python3
import argparse
import json
import socket
import sys
from typing import Dict, List, Set, Tuple

import requests
import dns.resolver

DEFAULT_SUBS = [
    "www","mail","owa","vpn","remote","portal","admin","api","dev","test","stage","staging",
    "prod","beta","static","cdn","assets","blog","docs","help","support",
    "ns1","ns2","autodiscover","m","webmail","smtp","imap","pop","ftp","git","jira","confluence",
]

UA = "dns-recon-script/1.0"


def dns_query(name: str, rtype: str, timeout: float = 2.5) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        answers = resolver.resolve(name, rtype)
        out = []
        for a in answers:
            out.append(str(a).strip())
        return out
    except Exception:
        return []


def resolve_host(host: str) -> Dict[str, List[str]]:
    return {
        "A": dns_query(host, "A"),
        "AAAA": dns_query(host, "AAAA"),
        "CNAME": dns_query(host, "CNAME"),
        "TXT": dns_query(host, "TXT"),
    }


def fetch_crtsh(domain: str, timeout: float = 10.0) -> Set[str]:
    """
    Pull subdomains from crt.sh (certificate transparency).
    Public OSINT, no auth required.
    """
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    subs: Set[str] = set()
    try:
        r = requests.get(url, params=params, headers={"User-Agent": UA}, timeout=timeout)
        if r.status_code != 200:
            return subs
        data = r.json()
        for row in data:
            nv = row.get("name_value", "")
            # name_value can contain multiple entries separated by newlines
            for name in str(nv).splitlines():
                name = name.strip().lower()
                if name.startswith("*."):
                    name = name[2:]
                if name.endswith("." + domain.lower()) or name == domain.lower():
                    subs.add(name)
    except Exception:
        pass
    return subs


def http_probe(host: str, timeout: float = 4.0) -> Dict[str, str]:
    """
    Minimal HTTP probe: just try HEAD over https/http and record status.
    """
    results = {}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = requests.head(url, allow_redirects=True, timeout=timeout, headers={"User-Agent": UA})
            results[scheme] = f"{r.status_code} -> {r.url}"
        except Exception as e:
            results[scheme] = f"ERR ({type(e).__name__})"
    return results


def load_wordlist(path: str) -> List[str]:
    subs = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            subs.append(s)
    return subs


def main() -> int:
    ap = argparse.ArgumentParser(description="Passive-ish DNS recon + crt.sh subdomain discovery + quick HTTP probing.")
    ap.add_argument("domain", help="Target domain (e.g. inlanefreight.com)")
    ap.add_argument("--wordlist", help="Optional subdomain wordlist (one per line). If omitted, uses a small built-in list.")
    ap.add_argument("--no-crt", action="store_true", help="Disable crt.sh subdomain discovery.")
    ap.add_argument("--probe", action="store_true", help="HTTP probe discovered hosts (HEAD requests).")
    ap.add_argument("--json", dest="json_out", help="Write results to JSON file.")
    args = ap.parse_args()

    domain = args.domain.strip().lower().rstrip(".")
    results: Dict[str, object] = {"domain": domain, "root": {}, "dns": {}, "subdomains": {}}

    # Root domain records
    results["root"] = {
        "NS": dns_query(domain, "NS"),
        "MX": dns_query(domain, "MX"),
        "SOA": dns_query(domain, "SOA"),
        "TXT": dns_query(domain, "TXT"),
        "A": dns_query(domain, "A"),
        "AAAA": dns_query(domain, "AAAA"),
    }

    # Discover candidate subdomains
    candidates: Set[str] = set()

    # Built-in + wordlist
    base = load_wordlist(args.wordlist) if args.wordlist else DEFAULT_SUBS
    for s in base:
        candidates.add(f"{s}.{domain}")

    # crt.sh
    if not args.no_crt:
        candidates |= fetch_crtsh(domain)

    # Resolve candidates
    for host in sorted(candidates):
        rec = resolve_host(host)
        has_any = any(rec[k] for k in ("A", "AAAA", "CNAME"))
        if not has_any:
            continue

        entry: Dict[str, object] = {"records": rec}
        if args.probe:
            entry["http"] = http_probe(host)
        results["subdomains"][host] = entry

    # Print a readable summary
    print(f"== {domain} ==")
    print("\n[Root DNS]")
    for k, v in results["root"].items():
        if v:
            print(f"{k}: {v}")

    print("\n[Resolved subdomains]")
    for host, data in results["subdomains"].items():
        rec = data["records"]
        parts = []
        if rec.get("CNAME"):
            parts.append("CNAME=" + ",".join(rec["CNAME"]))
        if rec.get("A"):
            parts.append("A=" + ",".join(rec["A"]))
        if rec.get("AAAA"):
            parts.append("AAAA=" + ",".join(rec["AAAA"]))
        line = f"- {host}  ({' | '.join(parts)})"
        print(line)
        if args.probe and "http" in data:
            print(f"    HTTP: {data['http']}")

    # Save JSON if requested
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Wrote JSON: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

