# Passive DNS Recon & Subdomain Discovery

A lightweight, passive-focused DNS reconnaissance tool that discovers subdomains using
certificate transparency (crt.sh), resolves DNS records, and optionally probes HTTP(S)
endpoints.

Designed for attack surface mapping, internal inventory, and authorized security testing.

---

## Features

- Passive subdomain discovery via:
  - Certificate Transparency (crt.sh)
  - Built-in subdomain wordlist
  - Optional custom wordlist
- DNS record resolution:
  - A, AAAA, CNAME, TXT, MX, NS, SOA
- Optional HTTP/HTTPS probing (HEAD requests)
- JSON output for automation and analysis
- No brute forcing, no credential harvesting

---

## Installation

```bash
git clone https://github.com/jkonpc/recon_dns.git
cd dns-recon
pip install -r requirements.txt
```

---

## Usage

Basic scan:

```python
python3 recon.py example.com
```

Disable certificate transparency:

```python
python3 recon.py example.com --no-crt
```

Use a custom subdomain wordlist:
```python
python3 recon.py example.com --wordlist subs.txt
```

Enable HTTP probing:
```python
python3 recon.py example.com --probe
```

Save results to JSON:
```python
python3 recon.py example.com --json output.json
```

---

## Example Output
```bash
== example.com ==

[Root DNS]
NS: ['ns1.example.com', 'ns2.example.com']
MX: ['mail.example.com']

[Resolved subdomains]
- www.example.com (A=93.184.216.34)
- mail.example.com (CNAME=mail.hosting.net)
    HTTP: {'https': '200 -> https://mail.example.com'}
```

---

## Design Notes

This tool is intentionally passive-first

Certificate Transparency provides historical visibility into exposed hosts

HTTP probing uses HEAD requests to minimize impact

DNS resolution failures are silently ignored to keep output clean

## Ethical Use

This tool is intended for:

Authorized security assessments

Defensive asset discovery

Personal learning and experimentation

Do not use against systems you do not own or have explicit permission to test.
