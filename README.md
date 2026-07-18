<div align="center">

# VENOM AI

### Virtual Engine for Network Offensive Monitoring

**An open-source, AI-augmented DAST (Dynamic Application Security Testing) platform.**
Actively scan your web apps for **OWASP Top 10:2025** vulnerabilities — with real attack payloads, AI-written explanations, and working code fixes.

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.11-green)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025-red)

</div>

---

## Legal Notice — Read First

VENOM AI sends **real attack payloads** (SQL injection, XSS, command injection, etc.) to the targets you scan. **Only scan systems you own or have explicit written permission to test.** Scanning systems without authorization is **illegal** under computer-misuse laws worldwide (CFAA in the US, the IT Act in India, the Computer Misuse Act in the UK, etc.).

By using VENOM you agree you are solely responsible for how you use it. See [DISCLAIMER.md](DISCLAIMER.md).

VENOM includes built-in guardrails to help you stay legal:
- **Domain ownership verification** before active scans (DNS TXT / file / meta-tag)
- **Forbidden-target blocklist** (government, military, banks, hospitals — never scanned)
- **Consent gate** on every active scan
- **Audit logging** of every scan attempt
- **Public demo targets** you can test on legally (Acunetix / OWASP test sites)

---

## What It Does

| Feature | Description |
|---|---|
| **Active OWASP Top 10:2025 scanner** | Sends real payloads to find *exploitable* bugs, not just missing headers — all 10 categories |
| **AI explanations + code fixes** | Every finding gets a plain-English explanation and a working fix in your app's language (Python/JS/PHP/etc.) |
| **VENOM AI security chat** | Scan-aware cybersecurity assistant — knows your findings, explains vulns, writes payloads, does live web/news search |
| **Groq + Ollama dual engine** | Groq cloud LLM by default; automatically falls back to a **local Ollama model** when Groq is rate-limited, so chat never stops working |
| **Free live web search, always on** | [SearXNG](https://searxng.org) runs as its own container — no API key, no rate limit, aggregates real search engines for current CVEs and news |
| **Tavily AI web search (optional upgrade)** | Accurate, AI-optimized search with a direct answer, used instead of SearXNG when a key is set |
| **OWASP ZAP deep scan** | Optional integration with the ZAP daemon for an industry-standard active scan alongside VENOM's own engines |
| **Hands-free voice agent** | JARVIS-style voice mode — talk to VENOM, it answers aloud with an animated 3D core (Chrome/Edge) |
| **Attack chain graphs** | Entry point to tools to attacker steps to impact, with MITRE ATT&CK mapping and animated flow |
| **True-positive verification** | Findings ranked by confidence (confirmed / probable / suspected) so you fix exploitable bugs first |
| **Reconnaissance engine** | Crawler, tech-stack fingerprinting, form discovery, endpoint enumeration, OSINT sweep |
| **AI attack planning** | Groq LLM plans which attacks fit the specific target |
| **Domain verification** | Prove ownership 4 ways before active scanning |
| **Continuous monitoring** | Re-scan targets on a schedule; desktop alerts on score drops |
| **Threat intelligence** | VirusTotal + CVE lookups |
| **PDF reports** | Professional, shareable security reports |
| **Built-in safety guardrails** | Rate limiting, forbidden targets, audit logs |

### Scanner engines — all 10 OWASP Top 10:2025 categories implemented
- **A01** Broken Access Control — IDOR, forced browsing, path traversal, JWT `alg=none`
- **A02** Security Misconfiguration — exposed `.env`/`.git`, debug pages, CORS, default creds
- **A03** Software Supply Chain — vulnerable JS libs, exposed manifests, missing SRI, EOL software
- **A04** Cryptographic Failures — HTTPS/HSTS/TLS, cookie flags, sensitive data in URLs
- **A05** Injection — SQLi (error/boolean/time), XSS, command injection, NoSQL, SSTI, XXE
- **A06** Insecure Design — missing rate limiting, business-logic flaws, weak defaults
- **A07** Authentication Failures — weak session handling, credential exposure, MFA gaps
- **A08** Software/Data Integrity — insecure deserialization signals, untrusted sources
- **A09** Security Logging & Alerting Failures — missing detection surfaces
- **A10** Mishandling of Exceptional Conditions — verbose errors, fail-open behavior, state leaks

---

## Try VENOM Live (No Install)

Want to see it working right now without installing anything? Open it in **GitHub Codespaces** — GitHub builds and runs the full stack (Postgres, Redis, API, worker, frontend) in the cloud, under **your own** free GitHub quota, and gives you a live URL in a few minutes.

1. On this repo, click **Code → Codespaces → Create codespace on main**
2. Wait for the containers to build (first run takes a few minutes)
3. Open the forwarded **port 3000** tab — that's your live VENOM AI
4. *(Optional, for AI features)* Paste a free [Groq key](https://console.groq.com) into `backend/.env` as `GROQ_API_KEY`, then run `docker compose restart api worker beat` in the Codespace terminal

> **⚠ Cost caution — read before leaving it running.** GitHub Codespaces gives every **free personal account 120 core-hours/month** (a 4-core machine, which VENOM's 6+ containers realistically need, uses 4 core-hours per real hour — about **30 hours/month free**). If you go over that:
> - With **no payment method on file, GitHub simply blocks further usage** — it does **not** silently charge you.
> - If you *do* add a payment method, overage is billed per machine size: **2-core $0.18/hr · 4-core $0.36/hr · 8-core $0.72/hr · 16-core $1.44/hr · 32-core $2.88/hr**, plus **$0.07/GB-month** over the free 15 GB storage.
> - **Stop or delete the codespace when you're done** (Codespaces tab on GitHub, or it auto-stops after ~30 min idle) so you don't burn your quota for nothing.

This spins up *your own private, isolated* instance — not a shared public server — so there's no risk of other people's scans colliding with yours, and no ongoing cost to the repo owner.

---

## Quick Start — Run It Yourself (5 minutes)

### Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- A free [Groq API key](https://console.groq.com) (for AI features — takes 2 minutes)

### Steps

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/venom-ai.git
cd venom-ai

# 2. Create your config from the template
cp backend/.env.example backend/.env      # Linux / Mac
# copy backend\.env.example backend\.env  # Windows

# 3. Open backend/.env and paste your Groq API key:
#      GROQ_API_KEY=gsk_your_key_here

# 4. Launch everything
docker compose up --build

# 5. Open your browser
#      Website:  http://localhost:3000
#      API docs: http://localhost:8000/api/docs
```

That's it. All six services (API, worker, scheduler, Postgres, Redis, frontend) start automatically.

---

## API Keys — What You Need

**You only strictly need ONE key: Groq** (free). Everything else is optional.

| Key | Required? | Free? | Get it at | Powers |
|---|---|---|---|---|
| **Groq** | Required for AI | Yes | [console.groq.com](https://console.groq.com) | Attack planning, explanations, code fixes, chatbot |
| **Tavily** | Optional | Yes (1k/mo) | [tavily.com](https://tavily.com) | Upgrades chat web search to Tavily's AI-ranked results + direct answer |
| **VirusTotal** | Optional | Yes (500/day) | [virustotal.com](https://virustotal.com) | Threat intel lookups |

> Web search itself needs **no key at all** — a [SearXNG](https://searxng.org) container ships in `docker-compose.yml` and powers chat search by default. Tavily is purely an optional upgrade for more accurate, AI-ranked results.

Full setup instructions for each key are inside [`backend/.env.example`](backend/.env.example).

### Groq Key Rotation (get 4x the free quota)

Groq's free tier limits requests **per key per day**. VENOM supports **up to 4 keys** and rotates automatically:

```
GROQ_API_KEY_1  ->  tried first
GROQ_API_KEY_2  ->  used if key 1 hits its rate limit (HTTP 429)
GROQ_API_KEY_3  ->  used if key 2 is also limited
GROQ_API_KEY_4  ->  final fallback
```

Make a few free Groq accounts (rate limits are per **account**, so use separate accounts, not extra keys on one account), drop the extra keys into `GROQ_API_KEY_1/2/3/4`, and VENOM stretches your free quota automatically. **One key is enough to start** — add more only if you scan heavily.

### Local AI fallback with Ollama (never hit a rate limit again)

When every Groq key is rate-limited, VENOM automatically falls back to a **local model running on your own machine** via [Ollama](https://ollama.com) — so the chat and AI explanations keep working, fully offline, at no cost.

```bash
# 1. Install Ollama (ollama.com), then pull a model:
ollama pull dolphin3

# 2. Tell VENOM which model you pulled (in backend/.env):
#      OLLAMA_MODEL=dolphin3
```

Ollama is **optional and only used as a fallback** — Groq stays primary because it's faster. VENOM reaches the host's Ollama daemon from inside Docker via `host.docker.internal`, which is wired up in `docker-compose.yml` out of the box. If Ollama isn't installed, VENOM simply shows a clear "rate-limited, try again later" message instead.

---

## How to Use

### 1. Open VENOM
Open http://localhost:3000 (or the forwarded port-3000 tab if you're in a Codespace — see [Using VENOM inside a Codespace](#using-venom-inside-a-codespace) below). It opens **straight to the dashboard**. VENOM is single-user by design — no login, no signup, no accounts — just like running OWASP ZAP or Burp on your own machine.

> Want the extra consent/domain-verification/scan-limit safety gates even on a single-operator install? Set `SINGLE_USER_MODE=false` in `backend/.env`.

The sidebar has every feature. Here's each one:

### 2. Dashboard
The landing page — total scans run, average security score, open vulnerabilities, a critical/high count, your most recent scans, and a severity breakdown. Empty until you run your first scan.

### 3. Scanner — the main scanning page
Enter a target URL and pick a scan type from the dropdown:

| Scan type | What it does |
|---|---|
| **⚡ OWASP Scanner** (`owasp2025`) | The real deal — active scanning, sends actual attack payloads (SQLi, XSS, command injection, etc.) across all 10 OWASP Top 10:2025 categories. **Requires authorization** (see step 4). |
| **Full Scan (Passive)** | Headers, SSL/TLS config, open ports (Nmap), tech fingerprinting — no attack payloads sent. |
| **Quick Scan** | A faster, lighter version of the full scan. |
| **Web App** | Focused on web-application-layer checks. |
| **Infrastructure** | Focused on network/port/service-level checks. |
| **Recon Only** | Just the crawler — discovers pages, forms, endpoints, tech stack. No testing at all. |

Only **OWASP Scanner** sends real attack traffic and requires the authorization step below — the other five are passive/read-only and can be pointed at anything without special authorization (they still shouldn't be run against systems you don't have permission to probe, but they don't send exploit payloads).

### 4. Authorize a target before an active (OWASP) scan
Pick **OWASP Scanner** and enter a URL — an authorization panel appears automatically and checks the domain:
- **Localhost / private IP** → allowed instantly, no verification needed
- **Public demo target** (`zero.webappsecurity.com`, `demo.testfire.net`, OWASP Juice Shop, DVWA, badssl.com, httpbin.org, etc.) → allowed instantly
- **Anything else** → shows "not yet verified" and an inline verification flow: pick ONE of DNS TXT record / file upload / `.well-known` file / `<meta>` tag, then click **Verify**

Either way, you must also tick **"I confirm I own this target or have written authorization to scan it"** — both the authorization check and the consent checkbox are enforced; **Launch Scan is blocked without both**, no matter what you type as the target.

### 5. Run the scan
Click **Launch Scan**. For OWASP scans you'll see each stage light up live: Recon → AI Attack Planning → A01…A10 → Verify Findings → Risk Matrix Scoring. Click **■ Stop Scan** any time to cancel.

### 6. Review findings
Results split into:
- **Vulnerabilities** — real, exploitable issues (with the payload that worked)
- **Hardening** — best-practice improvements

Each vulnerability includes an **AI explanation** in plain English, an **AI code fix** in your app's language (copy-paste ready), and — for OWASP scans — a place in the **Attack Chain Graph**.

### 7. Attack Chain Graph
Pick a completed scan from the dropdown (works for OWASP, quick, full, webapp, and infra scans) to see how its individual findings could be chained together by a real attacker to reach a critical asset — entry point → tools used → attacker steps → impact, mapped to MITRE ATT&CK techniques and tactics.

### 8. Compliance
Maps your scan findings onto **ISO 27001**, **SOC 2 Type II**, and **GDPR** controls — shows a compliance score per framework and exactly which findings are blocking which control. Needs at least one completed scan first.

### 9. NHI Scanner (Non-Human Identity)
A separate, fast, standalone check for leaked secrets in a site's public HTML/JS: AWS keys, GitHub tokens, Stripe/Google/Slack API keys, JWT secrets, SSH keys, database connection strings, and "shadow AI" tokens. Just enter a URL and click **Scan NHI** — no authorization gate, since it's read-only (fetches public pages and pattern-matches, sends no attack payloads).

### 10. Threat Intel
Three independent lookup tools against public databases — **nothing here touches the target's servers**, so it's safe to check any domain/IP/hash/CVE, including ones you don't own:
- **VirusTotal check** — paste a URL, domain, IP, or file hash; get a malicious/suspicious/harmless/undetected breakdown from 90+ antivirus engines, a reputation score, tags, and (for domains) registrar/WHOIS info. Requires `VIRUSTOTAL_API_KEY` in `.env` (free, 500 lookups/day).
- **CVE lookup** — type an exact CVE ID (e.g. `CVE-2024-3094`) to get its full record: description, CVSS score/severity, weaknesses, references.
- **CVE search** — type a keyword (a product, vendor, or vuln type like `wordpress` or `log4j`) to find matching CVEs. No key needed — both CVE features query NIST's public NVD database directly.
- **Recent CVEs** — pulls CVEs published in the last 30 days, optionally filtered by severity (Critical/High/Medium/Low).

### 11. Reports
Every completed scan can generate a PDF: executive summary, full vulnerability detail, and a remediation roadmap. **Generate Consolidated PDF** (top right) bundles every completed scan you have into one report — a cover page, a portfolio table, and one section per scan.

### 12. Continuous Monitoring
Add a target + interval (5 min / 30 min / hourly / daily / weekly) to re-scan it automatically. Turn on **"Alert on score drop"** and/or **"Alert on new vulns"**, and optionally **Enable Alerts** for desktop notifications. Every alert also lands in the **Alert History** list on the same page.

### 13. VENOM AI Chat (+ voice)
A scan-aware security assistant — it knows your latest findings and can explain vulnerabilities, write payloads/PoCs, walk through exploitation techniques on legal practice targets, and pull live CVE/news data via web search (SearXNG by default, no key needed — or Tavily if you've set `TAVILY_API_KEY` for more accurate results).
- **Voice mode** (Chrome/Edge): click the mic for a hands-free, JARVIS-style conversation — VENOM listens continuously and answers aloud with an animated 3D core. Click **End** to stop.
- **Edit a message**: every message you've sent shows a small pencil icon underneath it — click it to turn that message into an editable box in place, edit the text, then **Save & Submit**. This removes that message and everything after it (both on screen and from VENOM's memory of the conversation) and gets a fresh reply, exactly like editing a message in Claude or ChatGPT — it's not just "load it back into the input box."

### 14. Clear All Data
Bottom of the sidebar — wipes all scans, findings, and chat history for a completely fresh start. There's no undo.

---

## Using VENOM inside a Codespace

Everything above works identically in a Codespace — a few things are just worth knowing:

- **"localhost" means the Codespace's own container**, not your laptop. If you want to actively scan something local for testing, run it *inside* the Codespace terminal (e.g. `docker run -d -p 3000:3000 bkimminich/juice-shop` in the Codespace's own terminal), not on your physical machine.
- **AI chat needs your own Groq key** — paste one into `backend/.env` as `GROQ_API_KEY` (see [Try VENOM Live](#try-venom-live-no-install) above), then `docker compose restart api worker beat` from the Codespace terminal. Web search (SearXNG) and the scanner itself work with zero setup either way.
- **Ollama local-fallback won't work in a Codespace** — it needs a model running on your own physical machine, which a cloud Codespace can't reach. Not a problem in practice since Groq stays primary and each Codespace user has their own free Groq key/quota anyway.
- **Every visitor's Codespace is fully private and independent** — nobody shares scans, chat history, or quota with anyone else. See the cost caution in [Try VENOM Live](#try-venom-live-no-install) for what happens if you go over the free monthly hours.

---

## Changing config later (important)

Environment variables (API keys, model, mode) are read by the containers **at creation time**. After editing `backend/.env`, a plain `docker compose restart` will **not** pick up the change — recreate the containers instead:

```bash
docker compose up -d --force-recreate api worker beat
```

**Free Groq models** (defaults, both work out of the box):
`GROQ_MODEL=openai/gpt-oss-120b` (detailed answers) and `GROQ_MODEL_FAST=openai/gpt-oss-20b` (fast + voice).
Browse all models at [console.groq.com/docs/models](https://console.groq.com/docs/models) — use **Production** models only.

---

## Architecture

```
+-------------+     +--------------+     +-------------+
|  Frontend   |---->|  FastAPI     |---->|  PostgreSQL |
|  (nginx)    |     |  (API)       |     |             |
|  :3000      |     |  :8000       |     +-------------+
+-------------+     +------+-------+
                          |            +-------------+
                   +------v-------+    |    Redis    |
                   | Celery Worker|--->|  (broker)   |
                   | Celery Beat  |    +-------------+
                   +--------------+
```

**Stack:** FastAPI · Celery · PostgreSQL · Redis · Groq AI · Ollama (local fallback) · SearXNG (free web search) · Docker · Nginx · Vanilla JS SPA

**Scan pipeline:** `Recon -> AI Attack Plan -> Attack Engines (A01-A10) -> Verify -> AI Enrichment -> Risk Scoring -> Attack Chains`

Scanner tools bundled in the Docker image: **Nmap**, **Nuclei** (8000+ templates), **Nikto**. Optional **OWASP ZAP** daemon for a deep active scan.

---

## Configuration Reference

All configuration is via `backend/.env`. See [`backend/.env.example`](backend/.env.example) for the fully-documented template. Key settings:

| Variable | Default | Notes |
|---|---|---|
| `GROQ_API_KEY` | — | **Required** for AI |
| `OLLAMA_MODEL` | `dolphin3` | Local fallback model (must be pulled via `ollama pull`) |
| `TAVILY_API_KEY` | — | Optional; enables accurate AI web search |
| `ENV` | `development` | `production` hides `/api/docs` |
| `ALLOWED_ORIGINS` | localhost | Set to your domain in prod |
| `SINGLE_USER_MODE` | `true` | `false` adds consent/domain-verification/scan-limit gates |

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md). Good first areas:
- Building out the remaining A06–A10 attack engines
- Adding new tech-stack fingerprints to the recon engine
- Improving AI prompts for better explanations/fixes

---

## Reporting Security Issues in VENOM Itself

Found a vulnerability *in VENOM's own code*? Please report it privately — see [SECURITY.md](SECURITY.md).

---

## License

[Apache License 2.0](LICENSE) — free to use, modify, and distribute, including commercially.

---

<div align="center">

**Built for security professionals, students, and developers who want to find bugs before attackers do.**

Star this repo if VENOM helped you secure something.

</div>
