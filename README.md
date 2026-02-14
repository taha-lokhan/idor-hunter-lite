# IDOR – Insecure Direct Object Reference Scanner

A professional, CLI‑driven Python tool for detecting Insecure Direct Object Reference (IDOR) vulnerabilities in web APIs and applications.

## Features

- Fuzz URL templates with `{id}` placeholders (e.g., `https://target.com/api/users/{id}`).
- Send authenticated requests with custom headers (`--header "Authorization: Bearer ..."`).
- Analyze response differences by status code and body length.
- Progress‑bar‑driven scan with rich tables.
- Generate JSON, TXT, and HTML reports.
- HTML dashboard that opens automatically (`idor dashboard`).
- YAML‑based configuration for advanced scanning.
- Built with `httpx` (async), `click`, `rich`, and `jinja2`.
- Works through Burp / ZAP proxies via standard HTTP/HTTPS proxy settings.

---

## Installation

```bash
git clone https://github.com/yourusername/IDOR.git
cd IDOR
pip install -e .
