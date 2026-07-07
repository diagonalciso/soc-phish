# soc-Phish — Phishing Email Analyzer

> Parse suspicious emails and extract IOCs.

**Port:** `8091` &nbsp;|&nbsp; **Repo:** `diagonalciso/soc-phish` &nbsp;|&nbsp; **Service:** `soc-phish.service` &nbsp;|&nbsp; **Stack:** stdlib Python (no external deps)

Part of the **CD / Wazuh Full SOC** suite. Open the in-app **`?` Help button** (top-right of the dashboard) to read this manual, or view it here.

---

## 1. Overview

soc-Phish parses a suspicious email (headers + body), extracts indicators — URLs, domains, IPs, attachments — and gives a quick verdict to support user-reported-phish triage.

## 2. Key features

- Paste / submit an email for analysis
- Header and body parsing
- IOC extraction (URLs, domains, IPs)
- Verdict summary for fast triage

## 3. Running the service

The service is a single self-contained `app.py` using only the Python standard library.

```bash
# systemd (fleet / suite install)
sudo systemctl status soc-phish
sudo systemctl restart soc-phish
sudo journalctl -u soc-phish -f

# manual run (from the repo directory)
cp .env.example .env      # then edit as needed
env $(grep -v '^#' .env | xargs) python3 app.py
```

Then open **http://<host>:8091/**.

## 4. Configuration (environment variables)

Set these in `.env` (see `.env.example` for defaults):

| Variable | Notes |
|---|---|
| `MAX_UPLOAD_SIZE_MB` |  |
| `PHISHING_HOST` |  |
| `PHISHING_PORT` | Listen port (default 8091). |
| `SOCINT_API_URL` | Upstream service base URL. |
| `SOCINT_PASS` | Secret — keep out of git; set only in `.env`. |
| `SOCINT_USER` |  |

## 5. HTTP endpoints

| Path | |
|---|---|
| `/` | Main dashboard (HTML) |
| `/api/stats` | API endpoint (JSON) |
| `/manual` | This manual (opened by the top-right **?** Help button) |

## 6. Integration

Extracted IOCs can be pushed to soc-intel and pivoted in the SOC.

## 7. Security & operational notes

Treat submitted samples as potentially malicious; do not open extracted URLs directly.

## 8. Troubleshooting

| Symptom | Check |
|---|---|
| Page will not load | `systemctl status soc-phish`; confirm the port `8091` is listening (`lsof -i:8091`). |
| Help button shows "MANUAL.md not found" | Ensure `MANUAL.md` sits next to `app.py` in the service directory. |
| Service keeps restarting | `journalctl -u soc-phish -e` for the traceback; usually a missing `.env` value. |
| Empty / stale data | Confirm upstream sources and any API keys in `.env` are reachable. |

---

*Manual for soc-phish. Part of the CD / Wazuh Full SOC suite. Private © CisoDiagonal.*
