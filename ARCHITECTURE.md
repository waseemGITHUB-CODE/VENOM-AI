# CyberPlatform — Complete System Architecture

## Overview
AI-powered IT company platform combining:
- **AI Automation Services** — document processing, email automation, workflow automation
- **Cybersecurity Consulting** — vulnerability scanning, audit reports, pen-test workflows
- **SaaS Products** — dashboards, analytics, scalable API

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER BROWSER / CLIENT                     │
│              Next.js Dashboard + Chatbot UI                  │
└──────────────────────┬──────────────────────────────────────┘
                       │ HTTPS / REST API
┌──────────────────────▼──────────────────────────────────────┐
│                  FastAPI Backend (Port 8000)                  │
│                                                              │
│  /api/auth      — JWT authentication                        │
│  /api/chat      — Chatbot + intent routing                  │
│  /api/scanner   — Vulnerability scan API                    │
│  /api/documents — Document upload + extraction              │
│  /api/reports   — Report generation                         │
│  /api/dashboard — Stats & analytics                         │
└──────┬──────────────────────┬───────────────────────────────┘
       │                      │
┌──────▼──────┐     ┌─────────▼──────────────────────────────┐
│  PostgreSQL  │     │           Redis Task Queue              │
│  Database   │     │                                         │
│             │     │  Celery Workers (4 concurrent)          │
│  users      │     │  ┌─────────────────────────────────┐   │
│  documents  │     │  │ Worker 1: Document Processing   │   │
│  scan_jobs  │     │  │ Worker 2: Security Scanning     │   │
│  reports    │     │  │ Worker 3: Report Generation     │   │
│  jobs       │     │  │ Worker 4: Email Automation      │   │
└─────────────┘     │  └─────────────────────────────────┘   │
                    └────────────────────────────────────────-┘
                               │
                    ┌──────────▼──────────────┐
                    │      AI Layer (AI Engine)     │
                    │                         │
                    │  • Document extraction  │
                    │  • Vuln explanations    │
                    │  • Report generation    │
                    │  • Intent detection     │
                    └─────────────────────────┘
```

---

## Folder Structure

```
cyberplatform/
├── backend/
│   ├── main.py                    # FastAPI app entry point
│   ├── config.py                  # Environment settings
│   ├── database.py                # SQLAlchemy engine & session
│   ├── requirements.txt
│   ├── Dockerfile
│   │
│   ├── models/                    # SQLAlchemy ORM models
│   │   ├── user.py
│   │   ├── document.py            # Document + ExtractedData
│   │   ├── scan.py                # ScanJob + ScanResult + Vulnerability
│   │   ├── report.py
│   │   └── job.py                 # AutomationJob
│   │
│   ├── routers/                   # API route handlers
│   │   ├── auth.py                # JWT auth
│   │   ├── chat.py                # Chatbot controller
│   │   ├── scanner.py             # Vulnerability scan API
│   │   ├── documents.py           # Document upload & processing
│   │   ├── reports.py             # Report generation
│   │   └── dashboard.py           # Stats & analytics
│   │
│   ├── services/                  # Business logic layer
│   │   ├── ai_service.py          # AI Engine/OpenAI LLM calls
│   │   └── chat_service.py        # Intent detection & routing
│   │
│   └── workers/                   # Background job workers
│       ├── scanner.py             # Full security scanner engine
│       └── document_processor.py # PDF extraction & AI analysis
│
├── frontend/
│   └── index.html                 # Complete single-file dashboard
│
└── docker-compose.yml             # Full stack deployment
```

---

## API Endpoints

### Auth
| Method | Endpoint           | Description              |
|--------|--------------------|--------------------------|
| POST   | /api/auth/register | Register new user        |
| POST   | /api/auth/login    | Login → JWT token        |
| GET    | /api/auth/me       | Get current user         |

### Chatbot
| Method | Endpoint            | Description                   |
|--------|---------------------|-------------------------------|
| POST   | /api/chat/message   | Send message → get AI reply   |
| GET    | /api/chat/intents   | List all supported commands   |

### Security Scanner
| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| POST   | /api/scanner/start    | Start vulnerability scan |
| GET    | /api/scanner/{id}     | Get scan results         |
| GET    | /api/scanner/         | List all user scans      |

### Documents
| Method | Endpoint                   | Description                |
|--------|----------------------------|----------------------------|
| POST   | /api/documents/upload      | Upload PDF for processing  |
| GET    | /api/documents/            | List user's documents      |
| GET    | /api/documents/{id}        | Get document + extracted   |

### Reports
| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| POST   | /api/reports/generate | Generate a report        |
| GET    | /api/reports/         | List user's reports      |

### Dashboard
| Method | Endpoint              | Description              |
|--------|-----------------------|--------------------------|
| GET    | /api/dashboard/stats  | Aggregated platform stats|
| GET    | /api/dashboard/activity | Recent activity feed   |

---

## Database Schema

```sql
-- Users
CREATE TABLE users (
  id           UUID PRIMARY KEY,
  email        VARCHAR UNIQUE NOT NULL,
  full_name    VARCHAR,
  hashed_pw    VARCHAR NOT NULL,
  role         ENUM('admin','client','analyst') DEFAULT 'client',
  company_name VARCHAR,
  created_at   TIMESTAMP
);

-- Documents
CREATE TABLE documents (
  id           UUID PRIMARY KEY,
  owner_id     UUID REFERENCES users(id),
  filename     VARCHAR NOT NULL,
  doc_type     ENUM('invoice','contract','report','form','unknown'),
  status       ENUM('pending','processing','completed','failed'),
  raw_text     TEXT,
  ai_summary   TEXT,
  created_at   TIMESTAMP
);

-- Extracted Data (1:1 with documents)
CREATE TABLE extracted_data (
  id             UUID PRIMARY KEY,
  document_id    UUID REFERENCES documents(id),
  company_name   VARCHAR,
  invoice_number VARCHAR,
  invoice_amount FLOAT,
  invoice_date   VARCHAR,
  line_items     JSON,
  extra_fields   JSON
);

-- Scan Jobs
CREATE TABLE scan_jobs (
  id             UUID PRIMARY KEY,
  owner_id       UUID REFERENCES users(id),
  target_url     VARCHAR NOT NULL,
  status         ENUM('queued','running','completed','failed'),
  security_score FLOAT,
  started_at     TIMESTAMP,
  completed_at   TIMESTAMP
);

-- Vulnerabilities (many per scan)
CREATE TABLE vulnerabilities (
  id             UUID PRIMARY KEY,
  scan_job_id    UUID REFERENCES scan_jobs(id),
  title          VARCHAR NOT NULL,
  severity       ENUM('critical','high','medium','low','info'),
  description    TEXT,
  ai_explanation TEXT,
  recommendation TEXT,
  cvss_score     FLOAT,
  fixed          BOOLEAN DEFAULT FALSE
);

-- Reports
CREATE TABLE reports (
  id           UUID PRIMARY KEY,
  owner_id     UUID REFERENCES users(id),
  title        VARCHAR NOT NULL,
  report_type  ENUM('security_audit','document_extract','executive','automation'),
  content_json JSON,
  pdf_path     VARCHAR,
  created_at   TIMESTAMP
);

-- Automation Jobs
CREATE TABLE automation_jobs (
  id           UUID PRIMARY KEY,
  owner_id     UUID REFERENCES users(id),
  job_type     ENUM('document_processing','website_scan','report_generation','email_automation','workflow'),
  status       ENUM('pending','running','completed','failed'),
  input_data   JSON,
  output_data  JSON,
  progress_pct FLOAT DEFAULT 0,
  created_at   TIMESTAMP
);
```

---

## Chatbot Intent Routing

```
User Message
     │
     ▼
Intent Detection (keyword + regex)
     │
     ├─ "scan", "vuln", "audit", URL detected
     │         └──► scan_website → open Scanner, pre-fill URL
     │
     ├─ "invoice", "document", "extract", "pdf"
     │         └──► analyze_document → open Documents
     │
     ├─ "report", "summary", "findings"
     │         └──► generate_report → open Reports
     │
     ├─ "dashboard", "history", "my scans"
     │         └──► show_dashboard → navigate to Dashboard
     │
     ├─ "email", "inbox", "automate"
     │         └──► email_automation → open Email page
     │
     └─ anything else
               └──► general_help → show capabilities
```

---

## Security Scanner Checks

| Check                    | What it detects                          | Scoring Weight |
|--------------------------|------------------------------------------|----------------|
| Security Headers         | HSTS, CSP, X-Frame-Options, etc.         | 35%            |
| SSL/TLS                  | Certificate validity, expiry, config     | 30%            |
| Open Ports               | Risky services (MySQL, RDP, Redis, etc.) | 25%            |
| CMS Detection            | WordPress, Joomla, Drupal fingerprinting | 10%            |

---

## Quick Start

### 1. Prerequisites
```bash
# Install Docker
# Get AI Engine API key: https://console.groq.com (free)
```

### 2. Clone & Configure
```bash
git clone <repo>
cd cyberplatform
cp .env.example .env
# Edit .env: add AI_API_KEY, SECRET_KEY
```

### 3. Launch
```bash
docker compose up -d
```

### 4. Access
- **Frontend Dashboard:** http://localhost:3000  (or open frontend/index.html directly)
- **API Docs:**           http://localhost:8000/docs
- **Job Monitor:**        http://localhost:5555

### 5. Test the chatbot
Open the dashboard → click "AI Assistant" → type:
- `"Scan my website for vulnerabilities"`
- `"Analyze an invoice"`
- `"Generate a security report"`

---

## Technology Stack

| Layer          | Technology         | Purpose                          |
|----------------|--------------------|----------------------------------|
| Frontend       | HTML/CSS/JS        | Dashboard & chatbot UI           |
| Backend API    | Python + FastAPI   | REST API, auth, business logic   |
| Database       | PostgreSQL         | Persistent data storage          |
| Task Queue     | Redis + Celery     | Background job processing        |
| AI Layer       | AI Engine + LLaMA 3     | Extraction, explanations, reports|
| PDF Processing | PyMuPDF            | Text extraction from PDFs        |
| HTTP Client    | httpx              | Security header scanning         |
| Auth           | JWT (python-jose)  | Stateless authentication         |
| Containers     | Docker Compose     | Full-stack deployment            |

---

## Scaling Guide

### Horizontal Scaling
- Add more Celery workers: `--concurrency=8`
- Use multiple API replicas behind Nginx load balancer
- Upgrade PostgreSQL to connection pooling (PgBouncer)

### Production Checklist
- [ ] Change SECRET_KEY to 256-bit random value
- [ ] Use environment-specific .env files
- [ ] Enable HTTPS with SSL certificate (Let's Encrypt)
- [ ] Set up database backups
- [ ] Configure rate limiting on API
- [ ] Enable logging to file/syslog
- [ ] Set up monitoring (Prometheus + Grafana)
- [ ] Configure Redis persistence

---

*CyberPlatform v1.0 — Built with FastAPI + PostgreSQL + Redis + AI Engine AI*
