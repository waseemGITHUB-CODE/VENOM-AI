<div align="center">

# 🐍 VENOM AI

### Virtual Engine for Network Offensive Monitoring

**An open-source, AI-augmented DAST (Dynamic Application Security Testing) platform.**
Actively scan your web apps for **OWASP Top 10:2025** vulnerabilities — with real attack payloads, AI-written explanations, and working code fixes.

![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python](https://img.shields.io/badge/python-3.11-green)
![Docker](https://img.shields.io/badge/docker-ready-blue)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010%3A2025-red)

</div>

---

## ⚠️ Legal Notice — Read First

VENOM AI sends **real attack payloads** (SQL injection, XSS, command injection, etc.) to the targets you scan. **Only scan systems you own or have explicit written permission to test.** Scanning systems without authorization is **illegal** under computer-misuse laws worldwide (CFAA in the US, the IT Act in India, the Computer Misuse Act in the UK, etc.).

By using VENOM you agree you are solely responsible for how you use it. See [DISCLAIMER.md](DISCLAIMER.md).

VENOM includes built-in guardrails to help you stay legal:
- **Domain ownership verification** before active scans (DNS TXT / file / meta-tag)
- **Forbidden-target blocklist** (government, military, banks, hospitals — never scanned)
- **Consent gate** on every active scan
- **Audit logging** of every scan attempt
- **Public demo targets** you can test on legally (Acunetix / OWASP test sites)

---

## ✨ What It Does

| Feature | Description |
|---|---|
| 🎯 **Active OWASP Top 10:2025 scanner** | Sends real payloads to find *exploitable* bugs, not just missing headers — all 10 categories |
| 🤖 **AI explanations + code fixes** | Every finding gets a plain-English explanation and a working fix in your app's language (Python/JS/PHP/etc.) |
| 💬 **VENOM AI security chat** | Scan-aware cybersecurity assistant — knows your findings, explains vulns, writes payloads, does live web/news search |
| 🎙️ **Hands-free voice agent** | JARVIS-style voice mode — talk to VENOM, it answers aloud with an animated 3D core (Chrome/Edge) |
| 🧬 **Attack chain graphs** | Entry point → tools → attacker steps → impact, with MITRE ATT&CK mapping + animated flow |
| ✅ **True-positive verification** | Findings ranked by confidence (confirmed / probable / suspected) so you fix exploitable bugs first |
| 🔍 **Reconnaissance engine** | Crawler, tech-stack fingerprinting, form discovery, endpoint enumeration |
| 🧠 **AI attack planning** | Groq LLM plans which attacks fit the specific target |
| 🔐 **Domain verification** | Prove ownership 4 ways before active scanning |
| 📡 **Continuous monitoring** | Re-scan targets on a schedule; desktop alerts on score drops |
| 🌐 **Threat intelligence** | VirusTotal + CVE lookups |
| 📄 **PDF reports** | Professional, shareable security reports |
| 🛡️ **Built-in safety guardrails** | Rate limiting, forbidden targets, audit logs |

### Scanner engines — all 10 OWASP Top 10:2025 categories implemented
- ✅ **A01** Broken Access Control — IDOR, forced browsing, path traversal, JWT `alg=none`
- ✅ **A02** Security Misconfiguration — exposed `.env`/`.git`, debug pages, CORS, default creds
- ✅ **A03** Software Supply Chain — vulnerable JS libs, exposed manifests, missing SRI, EOL software
- ✅ **A04** Cryptographic Failures — HTTPS/HSTS/TLS, cookie flags, sensitive data in URLs
- ✅ **A05** Injection — SQLi (error/boolean/time), XSS, command injection, NoSQL, SSTI, XXE
- ✅ **A06** Insecure Design — missing rate limiting, business-logic flaws, weak defaults
- ✅ **A07** Authentication Failures — weak session handling, credential exposure, MFA gaps
- ✅ **A08** Software/Data Integrity — insecure deserialization signals, untrusted sources
- ✅ **A09** Security Logging & Alerting Failures — missing detection surfaces
- ✅ **A10** Mishandling of Exceptional Conditions — verbose errors, fail-open behavior, state leaks

---

## 🚀 Quick Start (5 minutes)

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
#    Also generate two random secrets (see .env.example instructions):
#      python -c "import secrets; print(secrets.token_hex(64))"

# 4. Launch everything
docker compose up --build

# 5. Open your browser
#      Website:  http://localhost:3000
#      API docs: http://localhost:8000/api/docs
```

That's it. All six services (API, worker, scheduler, Postgres, Redis, frontend) start automatically.

---

## 🔑 API Keys — What You Need

**You only strictly need ONE key: Groq** (free). Everything else is optional.

| Key | Required? | Free? | Get it at | Powers |
|---|---|---|---|---|
| **Groq** | ✅ Required for AI | ✅ Yes | [console.groq.com](https://console.groq.com) | Attack planning, explanations, code fixes, chatbot |
| **VirusTotal** | Optional | ✅ 500/day | [virustotal.com](https://virustotal.com) | Threat intel lookups |
| **Resend** | Optional | ✅ 3k/mo | [resend.com](https://resend.com) | Verification / reset emails |
| **Google OAuth** | Optional | ✅ Yes | [console.cloud.google.com](https://console.cloud.google.com) | "Sign in with Google" |
| **Gmail SMTP** | Optional | ✅ Yes | [myaccount.google.com](https://myaccount.google.com) | Alt email sender |

Full setup instructions for each key are inside [`backend/.env.example`](backend/.env.example).

### 🔄 Groq Key Rotation (get 4× the free quota)

Groq's free tier limits requests **per key per day**. VENOM supports **up to 4 keys** and rotates automatically:

```
GROQ_API_KEY    ->  tried first
GROQ_API_KEY_2  ->  used if key 1 hits its rate limit (HTTP 429)
GROQ_API_KEY_3  ->  used if key 2 is also limited
GROQ_API_KEY_4  ->  final fallback
```

Just make a few free Groq accounts, drop the extra keys into `GROQ_API_KEY_2/3/4`, and VENOM stretches your free quota up to 4× automatically. **One key is enough to start** — add more only if you scan heavily.

---

## 📖 How to Use

### 1. Open VENOM
Open http://localhost:3000 — it opens **straight to the dashboard**. By default VENOM runs in **single-user mode** (`SINGLE_USER_MODE=true`), so there's **no login or signup** — just like running OWASP ZAP or Burp on your own machine.

> Sharing one instance with a small team? Set `SINGLE_USER_MODE=false` in `backend/.env` to enable the full login/signup system (optionally with email verification via Resend/SMTP or "Sign in with Google").

### 2. Verify a domain you own
Before you can run an **active** scan on your own site, prove you own it:
- Go to the **Scanner** page → pick **"⚡ OWASP 2025 Active Scan"**
- Enter your URL → the authorization panel guides you through verification
- Pick any ONE method: DNS TXT record, upload a file, `.well-known` file, or a `<meta>` tag
- Click **Verify** → done

> **No domain?** You can scan public demo targets (like `http://zero.webappsecurity.com` or `http://demo.testfire.net`) or anything on `localhost` **without** verification — these are legal to test.

### 3. Run a scan
- Tick the consent box (confirming you're authorized)
- Click **Launch Scan**
- Watch each OWASP engine run live (Recon → AI Plan → A01…A05 → Verify → Risk)

### 4. Review findings
Results are split into:
- 🔴 **Vulnerabilities** — real, exploitable issues (with the payload that worked)
- 🟢 **Hardening** — best-practice improvements

Each vulnerability includes:
- 🤖 **AI explanation** in plain English
- ✨ **AI code fix** in your app's language (copy-paste ready)
- 🧬 **Attack chain** — how an attacker would exploit it, step by step, with tools + MITRE technique

### 5. (Optional) Monitor continuously
Add a target to **Continuous Monitoring** to re-scan it on a schedule and get alerted when its security posture changes.

### 6. Ask VENOM AI (chat + voice)
Open **VENOM AI Chat** for a scan-aware security assistant — it knows your latest findings, explains vulnerabilities, writes payloads, and does live web/news search for current CVEs.
- **Voice mode:** click the mic (Chrome/Edge) for a hands-free JARVIS-style conversation — VENOM listens continuously, answers aloud in a deep voice, and shows an animated 3D core. Click **End** to stop.

---

## ⚙️ Changing config later (important)

Environment variables (API keys, model, mode) are read by the containers **at creation time**. After editing `backend/.env`, a plain `docker compose restart` will **not** pick up the change — recreate the containers instead:

```bash
docker compose up -d --force-recreate api worker beat
```

**Free Groq models** (defaults, both work out of the box):
`GROQ_MODEL=openai/gpt-oss-120b` (detailed answers) · `GROQ_MODEL_FAST=openai/gpt-oss-20b` (fast + voice).
Browse all models at [console.groq.com/docs/models](https://console.groq.com/docs/models) — use **Production** models only.

---

## 🏗️ Architecture

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

**Stack:** FastAPI · Celery · PostgreSQL · Redis · Groq AI · Docker · Nginx · Vanilla JS SPA

**Scan pipeline:** `Recon -> AI Attack Plan -> Attack Engines (A01-A05) -> Verify -> AI Enrichment -> Risk Scoring -> Attack Chains`

Scanner tools bundled in the Docker image: **Nmap**, **Nuclei** (8000+ templates), **Nikto**.

---

## 🧩 Configuration Reference

All configuration is via `backend/.env`. See [`backend/.env.example`](backend/.env.example) for the fully-documented template. Key settings:

| Variable | Default | Notes |
|---|---|---|
| `GROQ_API_KEY` | — | **Required** for AI |
| `ENV` | `development` | `production` hides `/api/docs` |
| `ALLOWED_ORIGINS` | localhost | Set to your domain in prod |
| `FRONTEND_URL` | `localhost:3000` | Used in email links |

---

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md). Good first areas:
- Building out the remaining A06–A10 attack engines
- Adding new tech-stack fingerprints to the recon engine
- Improving AI prompts for better explanations/fixes

---

## 🔒 Reporting Security Issues in VENOM Itself

Found a vulnerability *in VENOM's own code*? Please report it privately — see [SECURITY.md](SECURITY.md).

---

## 📜 License

[Apache License 2.0](LICENSE) — free to use, modify, and distribute, including commercially.

---

<div align="center">

**Built for security professionals, students, and developers who want to find bugs before attackers do.**

⭐ Star this repo if VENOM helped you secure something.

</div>
