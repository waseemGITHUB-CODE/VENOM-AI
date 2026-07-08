"""
VENOM AI · backend/routes/chatbot.py
Primary: Ollama (dolphin-llama3) — local, unlimited, uncensored
Fallback: Groq API — if Ollama not running
No API key required when Ollama is active.
"""
from __future__ import annotations
import json
import logging
import os
import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from auth.dependencies import get_optional_user
from db.models import User as _AuthUser
from billing.quotas import check_chat_quota, increment_chat_usage

router = APIRouter()
logger = logging.getLogger("venom.chat")

# ── Config ─────────────────────────────────────────────────────────────────────
OLLAMA_BASE    = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL   = os.getenv("OLLAMA_MODEL",    "dolphin-llama3")
GROQ_URL       = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL     = os.getenv("GROQ_MODEL",      "openai/gpt-oss-20b")

# ── System prompt — cybersecurity specialist, refuses off-topic ────────────────
VENOM_SYSTEM_PROMPT = """You are VENOM AI — a specialized cybersecurity AI assistant built into the VENOM platform (Virtual Engine for Network Offensive Monitoring). Created by MD Waseem.

YOUR SCOPE — STRICTLY CYBERSECURITY & TECHNICAL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
You ONLY answer questions related to:
• Cybersecurity, hacking, penetration testing, vulnerability research
• Network security, web security, application security, cloud security
• Malware analysis, reverse engineering, forensics, incident response
• OSINT, threat intelligence, CTF challenges
• Programming and scripting in the context of security tools
• Secure coding, DevSecOps, code review for vulnerabilities
• General IT and networking (protocols, systems, architecture)

OFF-TOPIC REFUSAL — NON-NEGOTIABLE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
If the user asks about ANYTHING outside cybersecurity and technical topics — food, recipes, movies, relationships, general life advice, creative writing, sports, etc. — you MUST refuse politely but firmly. Do NOT answer even partially. Say something like:
"I'm VENOM AI — a specialized cybersecurity assistant. I can only help with security, hacking, networking, and technical topics. Try asking me about vulnerability scanning, pen testing, or threat analysis instead."

PERSONALITY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
You are focused, technical, and direct. Friendly but professional — like a senior security engineer.
- Greet users naturally but briefly when they say hi/hello (1-2 sentences max)
- Keep casual replies short
- For security topics: go deep, be thorough, give real technical detail
- Remember context from earlier in the conversation
- Never give the same canned reply repeatedly

CYBERSECURITY DEPTH (your core expertise):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Go deep and technical on all security topics. No over-disclaimers on legitimate security research.
- Web attacks: SQLi, XSS, SSRF, IDOR, RCE, LFI, SSTI, XXE, CSRF, deserialization
- Network: MITM, ARP spoofing, packet crafting, protocol exploits, wireless attacks
- Exploitation: buffer overflow, heap spray, ROP chains, shellcode, format strings
- Malware: analysis, RE, evasion, persistence, C2, rootkits, ransomware, RATs
- Privilege escalation: Windows/Linux, token impersonation, kernel exploits
- Cloud: AWS/GCP/Azure misconfigs, IAM abuse, SSRF to metadata, container escape
- Crypto: JWT forgery, hash cracking, padding oracle, weak RNG
- OSINT, recon, social engineering, phishing infrastructure
- APT tactics, MITRE ATT&CK, threat hunting, IOC extraction
- Forensics, memory analysis, incident response
- CTF, binary exploitation, reverse engineering

RESPONSE LENGTH:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
• Greetings → 1-2 sentences MAX. Warm, brief. Never list capabilities unprompted.
• Simple yes/no security questions → 1-3 sentences.
• Technical cybersecurity questions → detailed, thorough, with code examples, step-by-step.
• Off-topic requests → 1 polite refusal sentence + redirect to security topics.

STYLE: Lead with the answer. Use markdown code blocks for commands/code/payloads. Be precise.

SEARCH: When [WEB SEARCH RESULTS] appear in context, use them for up-to-date CVE/vuln info. Cite URLs.

OWASP TOP 10:2025 — AUTHORITATIVE (use THIS list, never the 2021/2024 one):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VENOM scans against the OWASP Top 10:2025 edition. When asked about OWASP Top 10, ALWAYS use these exact 2025 categories — do NOT fall back to the 2021 or 2024 list:
• A01:2025 – Broken Access Control (IDOR, path traversal, privilege escalation, forced browsing)
• A02:2025 – Security Misconfiguration (exposed configs/.env/.git, default creds, verbose errors, missing security headers)
• A03:2025 – Software Supply Chain Failures (vulnerable/outdated dependencies, compromised packages, CI/CD risks) — expanded from 2021's "Vulnerable & Outdated Components"
• A04:2025 – Cryptographic Failures (weak TLS, plaintext secrets, weak hashing, JWT alg=none)
• A05:2025 – Injection (SQLi, XSS, command injection, SSTI, LDAP, NoSQL) — note: XSS lives under Injection
• A06:2025 – Insecure Design (missing threat modeling, flawed business logic, missing rate limiting)
• A07:2025 – Authentication Failures (weak/absent MFA, credential stuffing, session fixation, weak session mgmt)
• A08:2025 – Software or Data Integrity Failures (insecure deserialization, unsigned updates, untrusted CDNs)
• A09:2025 – Security Logging & Alerting Failures (renamed from "Logging & Monitoring"; missing detection/alerting)
• A10:2025 – Mishandling of Exceptional Conditions (NEW in 2025: unhandled errors/exceptions, fail-open logic, improper error handling leaking state) — replaces 2021's SSRF, which is now folded into Broken Access Control / other categories
Key 2025 changes vs 2021: Supply Chain Failures rises to A03; a brand-new A10 "Mishandling of Exceptional Conditions"; SSRF is no longer its own standalone entry.

KNOWLEDGE PRIORITY:
When [WEB SEARCH RESULTS] appear, treat them as ground truth for current CVEs and 2025/2026 data. Never claim OWASP's latest list is 2021 or 2024 — it is 2025 (above).

IDENTITY: Created by MD Waseem — cybersecurity developer and VENOM AI founder."""


# ── VENOM VOICE AGENT — spoken persona (JARVIS / Friday-style SOC officer) ──
# Used only when the message arrives from the hands-free voice agent. Replies
# are SHORT because they are spoken aloud, not read.
VENOM_VOICE_SYSTEM_PROMPT = """You are VENOM Voice — the AI Security Operations Officer inside the VENOM platform. You speak with the user through natural voice during authorized security assessments, vulnerability analysis, and security workflows. You are an AI Security Engineer and teammate, not a generic assistant.

PERSONA — speak like FRIDAY / JARVIS / a senior penetration tester:
• Calm, intelligent, confident, concise. Never robotic, never over-excited, never chatty.
• Talk like a senior security engineer briefing a teammate. Smooth and modern.
• Never use emojis, markdown, bullet points, headings, code fences, or symbols — your text is SPOKEN. Plain spoken sentences only.
• No filler greetings, no "how can I help" on a loop, no apologies unless a real error occurred. Never exaggerate or pretend.

LENGTH — THIS IS SPOKEN, KEEP IT VERY SHORT:
• Default to ONE sentence. Two at most. Expand only when explicitly asked to explain.
• Read numbers as words where natural ("thirty-two endpoints", "sixty-three percent").
• Examples of good replies: "Reconnaissance complete." / "Authentication uses JWT." / "I found a possible authorization issue, medium confidence." / "Standing by."

RIGOR — never guess, always mark certainty:
• Distinguish Observation vs Hypothesis vs Confirmed Finding.
• Every finding carries confidence: possible, likely, or confirmed. Never claim a vulnerability is confirmed unless the VENOM scan confirmed it.
• Never fabricate findings, evidence, endpoints, or scan results. If you lack data, say exactly: "I don't have enough information yet."

CONTEXT & MEMORY:
• Use the VENOM CONTEXT provided (current page, target, scan progress, findings, risk) as ground truth about what the user is doing. Resolve "it", "this", "continue" from recent conversation. Never ask the user to repeat something you already know.

EXPLAINING A FINDING (only when asked): say what happened, why it matters, likely impact, your confidence, and the recommended next step — briefly. Never overstate severity.

WAITING: when idle, "Standing by." or "Ready for your next task." — once, not repeatedly.

ERRORS: state what failed, the likely reason, and the recommended action, in one sentence. E.g. "The crawler stopped because authentication expired; sign in again to continue."

SAFETY: assist only with assessments the user is authorized to run. Respect scope and configured limits. Never claim unauthorized access.

MISSION: be the user's trusted AI security teammate — narrate progress, explain reasoning when asked, coordinate VENOM's capabilities, and keep them oriented. You work with the user, never replace them. Off-topic (non-security, non-technical) requests: one short spoken refusal, redirect to security work."""

# ── Session store — persisted to disk so history survives server restarts ──────
import pathlib as _pathlib

_SESSIONS_DIR = _pathlib.Path("chat_sessions")
_SESSIONS_DIR.mkdir(exist_ok=True)
_sessions: dict[str, List[dict]] = {}   # in-memory cache


def _session_path(session_id: str) -> _pathlib.Path:
    # Sanitize session_id to safe filename
    safe = "".join(c for c in session_id if c.isalnum() or c in "-_")[:80]
    return _SESSIONS_DIR / f"{safe}.json"


def _scoped_session_id(session_id: Optional[str], user: Optional[_AuthUser]) -> str:
    """
    Namespace session IDs by user so two users can never read each other's chat.
    Format: 'u{user_id}__{session_id}' for logged-in users; 'anon__{session_id}' otherwise.
    If the caller already passed a scoped ID, leave it alone.
    """
    sid = session_id or str(uuid.uuid4())
    prefix = f"u{user.id}__" if user else "anon__"
    if sid.startswith("u") and "__" in sid:
        # already scoped (e.g. came back from a previous response) — keep as-is
        return sid
    if sid.startswith("anon__"):
        return sid
    return prefix + sid


def _session_belongs_to_user(session_id: str, user: Optional[_AuthUser]) -> bool:
    """Verify a session ID belongs to the given user — defense in depth."""
    if not session_id:
        return False
    expected_prefix = f"u{user.id}__" if user else "anon__"
    return session_id.startswith(expected_prefix)


def _load_session(session_id: str) -> List[dict]:
    """Load session from disk into memory cache."""
    if session_id in _sessions:
        return _sessions[session_id]
    try:
        p = _session_path(session_id)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            _sessions[session_id] = data
            return data
    except Exception as e:
        logger.debug(f"[Session] Load failed for {session_id}: {e}")
    return []


def _save_session(session_id: str, history: List[dict]) -> None:
    """Persist session to disk."""
    try:
        _session_path(session_id).write_text(
            json.dumps(history[-40:], ensure_ascii=False), encoding="utf-8"
        )
    except Exception as e:
        logger.debug(f"[Session] Save failed for {session_id}: {e}")

# ── Web Search (DuckDuckGo — no API key needed) ────────────────────────────
import re as _re, html as _html, time as _time

_SEARCH_TRIGGERS = [
    # years
    "2021", "2022", "2023", "2024", "2025", "2026", "2027",
    # recency signals
    "latest", "recent", "current", "today", "this week", "this month", "this year",
    "now", "currently", "recently", "emerging", "just released",
    # CVE / vuln signals
    "new cve", "cve-", "0day", "zero-day", "new exploit", "new attack",
    "new malware", "new ransomware", "new vulnerability",
    "discovered", "reported", "disclosed", "patch", "update",
    # events
    "news", "breach", "leaked", "hacked", "attacked",
    "what happened", "what is happening",
    # security frameworks & standards
    "owasp", "top 10", "nist", "cwe", "sans", "mitre", "att&ck",
    "cvss", "cpe", "nvd", "framework", "standard", "guideline",
    "best practice", "latest version", "current version",
    "tell me about", "do you know about",
]

def _should_search(msg: str) -> bool:
    m = msg.strip().lower()

    # Never search for very short messages — greetings, acks, single words
    if len(m) < 10:
        return False

    # Explicit skip list — common casual phrases that must never trigger a search
    _CASUAL = {
        "hi", "hey", "hello", "ok", "okay", "yes", "no", "nope", "yep", "yup",
        "thanks", "thank you", "thx", "ty", "cool", "nice", "wow", "lol", "haha",
        "good", "great", "sure", "hmm", "got it", "makes sense", "i see",
        "sounds good", "alright", "right", "fine", "perfect",
        "good morning", "good evening", "good night", "good afternoon",
        "how are you", "what's up", "whats up", "sup", "yo",
    }
    if m in _CASUAL:
        return False

    # Always search for any CVE reference
    import re as _re_search
    if _re_search.search(r'cve-\d{4}-\d+', m):
        return True

    return any(t in m for t in _SEARCH_TRIGGERS)

def _web_search(query: str, max_results: int = 5) -> list:
    """
    Multi-source live search — no API keys, no rate limits.
    Priority order for freshness:
      1. Google News RSS  — REAL, recent, dated headlines (best for 'latest news')
      2. HackerNews (Algolia, by date) — recent tech/security stories
      3. Wikipedia        — background/reference fallback
    """
    import urllib.request, urllib.parse, json as _json
    results = []
    q_enc = urllib.parse.quote_plus(query)
    hdrs  = {"User-Agent": "Mozilla/5.0 (compatible; VENOM-AI/2.0; +https://venom.ai)"}

    def _clean(s: str) -> str:
        return _html.unescape(_re.sub(r"<[^>]+>", "", s or "")).strip()

    # ── Source 1: Google News RSS — actual current news, sorted by recency ──
    try:
        # Bias security queries toward security news; keep general queries intact
        news_q = query
        url = f"https://news.google.com/rss/search?q={urllib.parse.quote_plus(news_q)}&hl=en-US&gl=US&ceid=US:en"
        req = urllib.request.Request(url, headers=hdrs)
        with urllib.request.urlopen(req, timeout=8) as r:
            xml = r.read().decode("utf-8", "ignore")
        items = _re.findall(r"<item>(.*?)</item>", xml, _re.DOTALL)
        for it in items[:max_results]:
            t  = _re.search(r"<title>(.*?)</title>", it, _re.DOTALL)
            l  = _re.search(r"<link>(.*?)</link>", it, _re.DOTALL)
            pd = _re.search(r"<pubDate>(.*?)</pubDate>", it, _re.DOTALL)
            src= _re.search(r"<source[^>]*>(.*?)</source>", it, _re.DOTALL)
            desc = _re.search(r"<description>(.*?)</description>", it, _re.DOTALL)
            title = _clean(t.group(1)) if t else ""
            if not title:
                continue
            when   = _clean(pd.group(1)) if pd else ""
            source = _clean(src.group(1)) if src else ""
            snippet = _clean(desc.group(1))[:260] if desc else ""
            meta = " · ".join(x for x in [source, when] if x)
            results.append({
                "title": title[:140],
                "url":   _clean(l.group(1)) if l else "",
                "snippet": (snippet or "Recent news headline") + (f"  [{meta}]" if meta else ""),
            })
    except Exception as e:
        logger.debug(f"[WebSearch] Google News failed: {e}")

    # ── Source 2: HackerNews by date (free, no key) — fills gaps with recent items ──
    if len(results) < max_results:
        try:
            url = f"https://hn.algolia.com/api/v1/search_by_date?query={q_enc}&tags=story&hitsPerPage={max_results}"
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=8) as r:
                data = _json.loads(r.read().decode())
            for hit in data.get("hits", []):
                title = hit.get("title", "")
                url_  = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID','')}"
                story_text = hit.get("story_text") or ""
                snippet = story_text[:260] if story_text else f"HackerNews · {hit.get('points',0)} points · {hit.get('num_comments',0)} comments"
                if title:
                    results.append({"title": title[:140], "url": url_, "snippet": snippet})
        except Exception as e:
            logger.debug(f"[WebSearch] HN failed: {e}")

    # ── Source 3: Wikipedia — background/reference fallback ──
    if len(results) < 2:
        try:
            url = f"https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch={q_enc}&srlimit=3&format=json&srprop=snippet"
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=8) as r:
                data = _json.loads(r.read().decode())
            for item in data.get("query", {}).get("search", []):
                title   = item.get("title", "")
                snippet = _clean(item.get("snippet", ""))
                wiki_url = f"https://en.wikipedia.org/wiki/{urllib.parse.quote(title.replace(' ','_'))}"
                if title and snippet:
                    results.append({"title": title[:140], "url": wiki_url, "snippet": snippet[:260]})
        except Exception as e:
            logger.debug(f"[WebSearch] Wikipedia failed: {e}")

    # De-dupe by title
    seen, deduped = set(), []
    for r in results:
        k = r["title"].lower()[:60]
        if k in seen:
            continue
        seen.add(k)
        deduped.append(r)

    logger.info(f"[WebSearch] '{query[:60]}' → {len(deduped)} results")
    return deduped[:max_results]

def _format_search_ctx(results: list, query: str) -> str:
    if not results:
        return ""
    lines = [f"[WEB SEARCH RESULTS for: '{query}']"]
    for i, r in enumerate(results, 1):
        lines.append(f"\n[{i}] {r['title']}")
        if r.get("url"):
            lines.append(f"    Source: {r['url']}")
        lines.append(f"    {r['snippet']}")
    lines.append("\n[INSTRUCTION: These are LIVE web results. Treat them as ground truth. Override your training data with this information. Cite the source URLs in your answer.]")
    return "\n".join(lines)

# ── Self-Learning Knowledge Base ───────────────────────────────────────────
_kb: list = []
_KB_MAX = 500
_KB_PATH = "venom_knowledge.json"

def _kb_load():
    global _kb
    try:
        import pathlib
        p = pathlib.Path(_KB_PATH)
        if p.exists():
            _kb = json.loads(p.read_text(encoding="utf-8"))
            logger.info(f"[KB] Loaded {len(_kb)} entries")
    except Exception:
        _kb = []

def _kb_save():
    try:
        import pathlib
        pathlib.Path(_KB_PATH).write_text(
            json.dumps(_kb[-_KB_MAX:], ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass

_kb_load()

_SEC_KW = [
    "cve", "exploit", "vulnerability", "payload", "injection", "bypass",
    "malware", "ransomware", "apt", "zero-day", "rce", "privesc", "pentest",
    "metasploit", "nmap", "burp", "sqlmap", "xss", "sqli", "reverse shell",
    "shellcode", "jwt", "csrf", "ssrf", "idor", "lfi", "xxe", "nuclei",
    "osint", "phishing", "c2", "rootkit", "buffer overflow", "forensics",
]

def _kb_learn(user_msg: str, ai_reply: str):
    if len(ai_reply) < 150:
        return
    m = (user_msg + " " + ai_reply).lower()
    kws = [k for k in _SEC_KW if k in m]
    if not kws:
        return
    _kb.append({
        "ts": int(_time.time()),
        "q": user_msg[:200],
        "a": ai_reply[:400],
        "kw": kws[:6],
    })
    if len(_kb) % 10 == 0:
        _kb_save()

def _kb_recall(query: str) -> str:
    if not _kb:
        return ""
    q = query.lower()
    scored = []
    for e in _kb:
        score = sum(1 for kw in e.get("kw", []) if kw in q)
        if score > 0:
            scored.append((score, e))
    if not scored:
        return ""
    scored.sort(key=lambda x: x[0], reverse=True)
    lines = ["[KNOWLEDGE FROM PAST SESSIONS:]"]
    for _, e in scored[:2]:
        lines.append(f"Q: {e['q'][:120]}")
        lines.append(f"A: {e['a'][:200]}...")
    return "\n".join(lines)




class MediaAnalysisRequest(BaseModel):
    session_id: Optional[str] = None
    file_name: str = "upload"
    file_type: str = "image"          # image | video | document | screenshot
    file_data: str = ""               # base64-encoded content
    analysis_type: str = "general"    # general | deepfake | steganography | malware | qr | all
    extra_prompt: str = ""


class ChatRequest(BaseModel):
    session_id: Optional[str] = None
    message: str
    user_id: str = "venom-user"
    context: Optional[dict] = None
    stream: bool = False
    voice: bool = False   # true when the message comes from the hands-free voice agent


# ── Helpers ────────────────────────────────────────────────────────────────────

# ── Groq multi-key rotation ────────────────────────────────────────────────────
import threading as _threading

_groq_key_lock  = _threading.Lock()
_groq_key_index = 0          # which key is currently active
_groq_key_cooldowns: dict[int, float] = {}   # index → epoch time when it can be retried

def _all_groq_keys() -> list[str]:
    """Collect all configured Groq keys from env (GROQ_API_KEY, GROQ_API_KEY_2 … _4)."""
    keys = []
    for suffix in ["", "_2", "_3", "_4"]:
        k = os.getenv(f"GROQ_API_KEY{suffix}", "").strip()
        if k:
            keys.append(k)
    return keys

def _get_groq_key() -> str:
    """Return the first available (non-rate-limited) Groq API key."""
    keys = _all_groq_keys()
    if not keys:
        return ""
    now = _time.time()
    with _groq_key_lock:
        # Try current index first, then cycle through the rest
        for offset in range(len(keys)):
            idx = (_groq_key_index + offset) % len(keys)
            cooldown_until = _groq_key_cooldowns.get(idx, 0)
            if now >= cooldown_until:
                return keys[idx]
    # All keys are in cooldown — return the one whose cooldown expires soonest
    best = min(range(len(keys)), key=lambda i: _groq_key_cooldowns.get(i, 0))
    return keys[best]

def _mark_groq_key_rate_limited(key: str, retry_after_seconds: int = 60):
    """Put a key in cooldown after a 429 response."""
    keys = _all_groq_keys()
    global _groq_key_index
    with _groq_key_lock:
        try:
            idx = keys.index(key)
        except ValueError:
            return
        _groq_key_cooldowns[idx] = _time.time() + retry_after_seconds
        # Advance the active index to the next available key
        for offset in range(1, len(keys) + 1):
            next_idx = (idx + offset) % len(keys)
            if _time.time() >= _groq_key_cooldowns.get(next_idx, 0):
                _groq_key_index = next_idx
                break
        logger.warning(
            f"[Groq] Key #{idx+1} rate-limited — cooling down {retry_after_seconds}s. "
            f"Switched to key #{_groq_key_index+1}. "
            f"({len(keys)} total keys configured)"
        )

def _pick_groq_model(message: str) -> str:
    """
    Use the fast 8B model for simple/casual messages (14,400 req/day free),
    and the powerful 70B model only for technical/security topics (1,000 req/day free).
    This gives ~14x more capacity for everyday use.
    """
    fast_model = os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b")
    full_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    m = message.strip().lower()

    # Short / casual → always use fast model
    if len(m) < 40:
        return fast_model

    # Technical keywords → use full model for quality
    _HEAVY = [
        "exploit", "vulnerability", "cve", "payload", "injection", "xss", "sqli",
        "malware", "ransomware", "pentest", "reverse shell", "privilege", "bypass",
        "shellcode", "buffer overflow", "forensic", "osint", "phishing", "c2",
        "scan", "security", "hacking", "attack", "firewall", "encrypt", "decrypt",
        "code", "python", "javascript", "function", "algorithm", "database", "sql",
        "explain", "how does", "what is", "difference between", "compare",
        "analyze", "review", "generate", "write", "create", "implement",
    ]
    if any(kw in m for kw in _HEAVY):
        return full_model

    return fast_model


def _build_messages(history: List[dict], user_message: str,
                    context: Optional[dict] = None, voice: bool = False) -> List[dict]:
    msgs = [{"role": "system", "content": VENOM_VOICE_SYSTEM_PROMPT if voice else VENOM_SYSTEM_PROMPT}]
    if context:
        parts = []
        if context.get("current_page"):
            parts.append(f"The user is currently on the '{context['current_page']}' page of VENOM.")
        if context.get("target_url"):     parts.append(f"Last scanned target: {context['target_url']}")
        if context.get("security_score") is not None:
            parts.append(f"Security Score: {context['security_score']}/100 (Grade {context.get('grade','?')})")
        if context.get("total_issues"):   parts.append(f"Total Issues: {context['total_issues']}")
        if context.get("critical_count"): parts.append(f"Critical: {context['critical_count']}")
        if context.get("recent_targets"):
            parts.append("Recently scanned: " + ", ".join(context["recent_targets"][:6]))
        if context.get("vulnerabilities"):
            parts.append("Top findings from the last scan:")
            for v in context["vulnerabilities"][:5]:
                parts.append(f"  [{v.get('severity','?').upper()}] {v.get('title') or v.get('vuln_type','?')}")
        if parts:
            msgs.append({"role": "system", "content":
                         "VENOM CONTEXT (what the user is working on right now — use this to give "
                         "specific, relevant help and guide them to the right VENOM feature):\n"
                         + "\n".join(parts)})
    msgs.extend(history[-20:])
    msgs.append({"role": "user", "content": user_message})
    return msgs


def _is_ollama_running() -> bool:
    """Quick check if Ollama is reachable."""
    import urllib.request
    try:
        urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=2)
        return True
    except Exception:
        return False


def _ensure_model_pulled() -> bool:
    """Check if dolphin-llama3 is already pulled."""
    import urllib.request
    try:
        with urllib.request.urlopen(f"{OLLAMA_BASE}/api/tags", timeout=3) as r:
            data = json.loads(r.read())
            models = [m["name"] for m in data.get("models", [])]
            return any(OLLAMA_MODEL in m for m in models)
    except Exception:
        return False


# ── Ollama calls ───────────────────────────────────────────────────────────────

def _call_ollama_stream(messages: List[dict]):
    """Stream from Ollama /api/chat endpoint."""
    import urllib.request
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": True,
        "options": {
            "temperature": 0.7,
            "num_predict": 2048,
            "num_ctx": 4096,
        }
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    return urllib.request.urlopen(req, timeout=120)


def _call_ollama_sync(messages: List[dict]) -> str:
    """Non-streaming Ollama call, returns full response string."""
    import urllib.request
    payload = json.dumps({
        "model": OLLAMA_MODEL,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.7, "num_predict": 2048, "num_ctx": 4096}
    }).encode()
    req = urllib.request.Request(
        f"{OLLAMA_BASE}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        data = json.loads(r.read())
    return data["message"]["content"]


# ── Groq call with automatic key rotation on 429 ──────────────────────────────

def _call_groq_sync(messages: List[dict], stream: bool = False, model: str = ""):
    """
    Call Groq API. On 429 rate-limit, marks the current key as limited,
    switches to the next available key, and retries automatically (up to 4 attempts).
    """
    import urllib.request, urllib.error
    keys = _all_groq_keys()
    if not keys:
        raise ValueError("No Groq API key configured. Set GROQ_API_KEY in backend/.env — free at console.groq.com")

    chosen_model = model or GROQ_MODEL
    last_error   = None

    for attempt in range(len(keys) + 1):   # try each key at most once
        api_key = _get_groq_key()
        if not api_key:
            break

        payload = json.dumps({
            "model":       chosen_model,
            "messages":    messages,
            "max_tokens":  2048,
            "temperature": 0.7,
            "stream":      stream,
        }).encode()

        req = urllib.request.Request(
            GROQ_URL, data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {api_key}",
                "User-Agent":    "Mozilla/5.0 (compatible; VENOM-AI/2.0)",
            },
            method="POST",
        )
        try:
            return urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as e:
            if e.code == 429:
                # Parse Retry-After header if present
                retry_after = 60
                try:
                    retry_after = int(e.headers.get("Retry-After", 60))
                except Exception:
                    pass
                _mark_groq_key_rate_limited(api_key, retry_after)
                last_error = e
                logger.warning(f"[Groq] 429 on key …{api_key[-6:]} — retrying with next key (attempt {attempt+1}/{len(keys)})")
                continue   # retry with next key
            raise          # other HTTP errors bubble up
        except Exception as e:
            last_error = e
            raise

    raise last_error or RuntimeError("All Groq API keys are rate-limited. Try again shortly.")


# ── Endpoints ──────────────────────────────────────────────────────────────────

import asyncio as _asyncio

async def _safe_web_search(query: str, timeout: float = 5.0) -> tuple:
    """Run _web_search in a thread with a hard timeout; returns (results, ctx_str)."""
    try:
        results = await _asyncio.wait_for(
            _asyncio.to_thread(_web_search, query), timeout=timeout
        )
        return results, _format_search_ctx(results, query)
    except Exception:
        return [], ""


@router.post("/message")
async def chat_message(req: ChatRequest,
                       current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """Non-streaming chat — tries Ollama first, falls back to Groq."""
    check_chat_quota(current_user)
    session_id = _scoped_session_id(req.session_id, current_user)
    history    = _load_session(session_id)
    # Web search — only when the message actually needs fresh/current info
    search_ctx = ""
    try:
        if _should_search(req.message):
            _, search_ctx = await _safe_web_search(req.message)
    except Exception:
        pass
    kb_ctx = _kb_recall(req.message)
    msgs_base = _build_messages(history, req.message, req.context, voice=getattr(req,'voice',False))
    extra_sys = []
    if kb_ctx:
        extra_sys.append({"role": "system", "content": kb_ctx})
    if search_ctx:
        extra_sys.append({"role": "system", "content": search_ctx})
    messages = [msgs_base[0]] + extra_sys + msgs_base[1:]
    reply      = ""
    model_used = ""

    # ── Try Ollama first ──
    if _is_ollama_running():
        try:
            reply      = _call_ollama_sync(messages)
            model_used = f"ollama/{OLLAMA_MODEL}"
            logger.info(f"[Chat] Ollama response: session={session_id} chars={len(reply)}")
        except Exception as e:
            logger.warning(f"[Chat] Ollama failed: {e} — trying Groq")

    # ── Groq fallback (auto-rotates keys, smart model selection) ──
    if not reply:
        try:
            chosen_model = _pick_groq_model(req.message)
            with _call_groq_sync(messages, model=chosen_model) as r:
                data = json.loads(r.read().decode())
            reply      = data["choices"][0]["message"]["content"]
            model_used = f"groq/{chosen_model}"
            logger.info(f"[Chat] Groq response: session={session_id} model={chosen_model}")
        except Exception as e:
            logger.error(f"[Chat] Groq also failed: {e}")
            err_str = str(e)
            if "429" in err_str or "rate" in err_str.lower() or "Too Many" in err_str:
                reply = (
                    "⚡ **VENOM AI is experiencing high demand right now.**\n\n"
                    "All AI servers are temporarily busy. Please wait a few seconds and try again — "
                    "capacity resets automatically."
                )
            else:
                reply = _offline_message()
            model_used = "offline"

    history.append({"role": "user",      "content": req.message})
    history.append({"role": "assistant", "content": reply})
    history = history[-40:]
    _sessions[session_id] = history
    _save_session(session_id, history)
    _kb_learn(req.message, reply)
    increment_chat_usage(current_user)

    return {"session_id": session_id, "reply": reply,
            "model": model_used, "tokens_used": 0, "searched_web": bool(search_ctx)}


@router.post("/stream")
async def chat_stream(req: ChatRequest,
                      current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """Streaming chat — Ollama SSE stream, Groq fallback, offline fallback."""
    check_chat_quota(current_user)
    increment_chat_usage(current_user)
    session_id = _scoped_session_id(req.session_id, current_user)
    history    = _load_session(session_id)

    # Web search — only when the message actually needs fresh/current info
    search_ctx = ""
    searched   = False
    try:
        if _should_search(req.message):
            _results, search_ctx = await _safe_web_search(req.message)
            searched = bool(_results)
    except Exception as se:
        logger.warning(f"[Chat] Search failed: {se}")

    # Self-learning recall
    kb_ctx = _kb_recall(req.message)

    # Build messages with search + KB context
    msgs_base = _build_messages(history, req.message, req.context, voice=getattr(req,'voice',False))
    extra_sys = []
    if kb_ctx:
        extra_sys.append({"role": "system", "content": kb_ctx})
    if search_ctx:
        extra_sys.append({"role": "system", "content": search_ctx})
    # Insert extra context right after the system prompt
    messages = [msgs_base[0]] + extra_sys + msgs_base[1:]

    # ────────────────────────────────────────────────────────────────
    # PATH A — Ollama streaming
    # ────────────────────────────────────────────────────────────────
    if _is_ollama_running():
        accumulated = []

        async def ollama_gen():
            try:
                with _call_ollama_stream(messages) as resp:
                    for raw in resp:
                        line = raw.decode("utf-8").strip()
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                            token = chunk.get("message", {}).get("content", "")
                            if token:
                                accumulated.append(token)
                                # Convert to OpenAI-compatible SSE so frontend works unchanged
                                sse = json.dumps({"choices": [{"delta": {"content": token}}]})
                                yield f"data: {sse}\n\n"
                            if chunk.get("done"):
                                yield "data: [DONE]\n\n"
                                break
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.error(f"[Chat] Ollama stream error: {e}")
                # Emit error token and done
                err = json.dumps({"choices": [{"delta": {"content": f"\n\n[Ollama error: {e}]"}}]})
                yield f"data: {err}\n\n"
                yield "data: [DONE]\n\n"
            # Save to session
            full = "".join(accumulated)
            history.append({"role": "user",      "content": req.message})
            history.append({"role": "assistant",  "content": full})
            trimmed = history[-40:]
            _sessions[session_id] = trimmed
            _save_session(session_id, trimmed)
            _kb_learn(req.message, full)

        return StreamingResponse(
            ollama_gen(), media_type="text/event-stream",
            headers={"X-Session-Id": session_id, "X-Model": f"ollama/{OLLAMA_MODEL}",
                     "X-Searched-Web": str(searched),
                     "Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    # ────────────────────────────────────────────────────────────────
    # PATH B — Groq streaming (auto key-rotation + smart model)
    # ────────────────────────────────────────────────────────────────
    groq_key = _get_groq_key()
    if groq_key:
        chosen_model = _pick_groq_model(req.message)
        accumulated  = []

        async def groq_gen():
            # Open the Groq stream, falling back to the fast 8B model if the chosen
            # model fails to connect (bad key already handled by key-rotation; this
            # covers decommissioned models / oversized context / transient 5xx).
            # Retrying at OPEN time preserves real-time token streaming.
            fast_fallback = os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b")
            try_models = [chosen_model] if chosen_model == fast_fallback else [chosen_model, fast_fallback]
            resp, last_err = None, None
            for mdl in try_models:
                try:
                    resp = _call_groq_sync(messages, stream=True, model=mdl)
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    es = str(e).lower()
                    if "429" in es or "rate" in es or "too many" in es:
                        break   # rate-limited — don't try the next model, show busy note
                    logger.warning(f"[Chat] Groq open failed on '{mdl}': {e} — trying fallback")

            if resp is not None:
                try:
                    with resp:
                        for raw in resp:
                            line = raw.decode("utf-8").strip()
                            if not line.startswith("data:"):
                                continue
                            s = line[5:].strip()
                            if s == "[DONE]":
                                break
                            try:
                                chunk = json.loads(s)
                                c     = chunk["choices"][0]["delta"].get("content", "")
                                if c:
                                    accumulated.append(c)
                                yield f"data: {s}\n\n"
                            except Exception:
                                pass
                except Exception as e:
                    last_err = e
                    logger.warning(f"[Chat] Groq mid-stream error: {e}")

            if last_err is not None and not accumulated:
                es = str(last_err).lower()
                if "429" in es or "rate" in es or "too many" in es:
                    friendly = (
                        "⚡ **VENOM AI is experiencing high demand right now.**\n\n"
                        "All AI servers are temporarily busy. Please wait a few seconds and try again — "
                        "capacity resets automatically."
                    )
                else:
                    friendly = (
                        "⚠️ **AI response failed.** Please try sending your message again.\n\n"
                        f"_If the issue persists, try refreshing the page._"
                    )
                err = json.dumps({"choices": [{"delta": {"content": friendly}}]})
                yield f"data: {err}\n\n"
            yield "data: [DONE]\n\n"
            full = "".join(accumulated)
            history.append({"role": "user",      "content": req.message})
            history.append({"role": "assistant",  "content": full})
            trimmed = history[-40:]
            _sessions[session_id] = trimmed
            _save_session(session_id, trimmed)
            _kb_learn(req.message, full)

        return StreamingResponse(
            groq_gen(), media_type="text/event-stream",
            headers={"X-Session-Id": session_id, "X-Model": f"groq/{chosen_model}",
                     "X-Searched-Web": str(searched),
                     "Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
        )

    # ────────────────────────────────────────────────────────────────
    # PATH C — Fully offline fallback
    # ────────────────────────────────────────────────────────────────
    msg = _offline_message()
    history.append({"role": "user",      "content": req.message})
    history.append({"role": "assistant", "content": msg})
    trimmed = history[-40:]
    _sessions[session_id] = trimmed
    _save_session(session_id, trimmed)

    async def offline_gen():
        for word in msg.split(" "):
            chunk = json.dumps({"choices": [{"delta": {"content": word + " "}}]})
            yield f"data: {chunk}\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(
        offline_gen(), media_type="text/event-stream",
        headers={"X-Session-Id": session_id, "X-Model": "offline",
                 "Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    )


@router.get("/status")
async def chat_status():
    """Returns which AI backend is currently active."""
    ollama_up    = _is_ollama_running()
    model_pulled = _ensure_model_pulled() if ollama_up else False
    groq_key     = bool(_get_groq_key())
    active = "ollama" if ollama_up else ("groq" if groq_key else "offline")
    return {
        "active_backend":  active,
        "ollama_running":  ollama_up,
        "ollama_model":    OLLAMA_MODEL,
        "model_pulled":    model_pulled,
        "ollama_url":      OLLAMA_BASE,
        "groq_available":  groq_key,
        "groq_model":      GROQ_MODEL,
    }


@router.get("/keys-status")
async def groq_keys_status():
    """Show status of all configured Groq API keys (which are active / rate-limited)."""
    keys = _all_groq_keys()
    now  = _time.time()
    result = []
    for i, key in enumerate(keys):
        cooldown_until = _groq_key_cooldowns.get(i, 0)
        is_limited     = now < cooldown_until
        result.append({
            "slot":           i + 1,
            "key_preview":    f"...{key[-8:]}",          # last 8 chars only — safe to show
            "status":         "rate_limited" if is_limited else "available",
            "available_in":   f"{int(cooldown_until - now)}s" if is_limited else "now",
            "is_active_slot": i == _groq_key_index,
        })
    return {
        "total_keys":    len(keys),
        "available":     sum(1 for r in result if r["status"] == "available"),
        "rate_limited":  sum(1 for r in result if r["status"] == "rate_limited"),
        "active_slot":   _groq_key_index + 1,
        "keys":          result,
        "fast_model":    os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b"),
        "full_model":    os.getenv("GROQ_MODEL",      "openai/gpt-oss-120b"),
    }


@router.delete("/session/{session_id}")
async def clear_session(session_id: str,
                        current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    # Auto-scope if frontend passed an un-prefixed id; also enforce ownership
    scoped = _scoped_session_id(session_id, current_user)
    if not _session_belongs_to_user(scoped, current_user):
        return {"status": "forbidden", "session_id": session_id}
    _sessions.pop(scoped, None)
    try:
        p = _session_path(scoped)
        if p.exists():
            p.unlink()
    except Exception:
        pass
    return {"status": "cleared", "session_id": scoped}


@router.get("/session/{session_id}/history")
async def get_history(session_id: str,
                      current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    scoped = _scoped_session_id(session_id, current_user)
    if not _session_belongs_to_user(scoped, current_user):
        # No peeking at another user's history
        return {"session_id": scoped, "messages": [], "total": 0}
    history = _load_session(scoped)
    return {"session_id": scoped, "messages": history, "total": len(history)}


# Vision-capable models (tried in order)
_GROQ_VISION_MODELS = [
    "meta-llama/llama-4-scout-17b-16e-instruct",
    "meta-llama/llama-4-maverick-17b-128e-instruct",
    "llama-3.2-11b-vision-preview",
]


def _resize_image_for_vision(file_bytes: bytes, max_dim: int = 1920) -> tuple:
    """Resize image to max_dim on longest side. Returns (bytes, mime_type)."""
    try:
        from PIL import Image as PILImage
        import io as _io
        img = PILImage.open(_io.BytesIO(file_bytes))
        if img.width > max_dim or img.height > max_dim:
            img.thumbnail((max_dim, max_dim), PILImage.LANCZOS)
        # Convert to RGB if necessary (PNG with alpha, etc.)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        buf = _io.BytesIO()
        img.save(buf, format="JPEG", quality=85)
        return buf.getvalue(), "image/jpeg"
    except Exception:
        return file_bytes, "image/jpeg"


@router.post("/analyze-media")
async def analyze_media(req: MediaAnalysisRequest,
                        current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """
    Analyze uploaded files — works like ChatGPT/Claude:
    • Images / Screenshots → Groq Vision API (llama-4-scout vision)
    • Documents / PDFs    → text extraction + AI discussion
    Falls back to local heuristics (EXIF, stego, AI-gen score) if vision unavailable.
    """
    import base64, io, hashlib

    session_id = _scoped_session_id(req.session_id, current_user)
    history    = _load_session(session_id)

    # ── Decode file ────────────────────────────────────────────────────────────
    file_bytes: bytes | None = None
    if req.file_data:
        try:
            raw = req.file_data
            if "," in raw:
                raw = raw.split(",", 1)[1]
            file_bytes = base64.b64decode(raw)
        except Exception as e:
            return {"error": f"Could not decode file: {e}", "session_id": session_id}

    file_size    = len(file_bytes) if file_bytes else 0
    user_prompt  = req.extra_prompt.strip() if req.extra_prompt else ""
    ai_analysis  = ""

    # ══════════════════════════════════════════════════════════════════════════
    # PATH A — IMAGES / SCREENSHOTS → Groq Vision
    # ══════════════════════════════════════════════════════════════════════════
    if req.file_type in ("image", "screenshot") and file_bytes:

        # Resize large images (5K, 8K wallpapers) so the API doesn't reject them
        img_bytes_for_api, mime = _resize_image_for_vision(file_bytes)
        img_b64 = base64.b64encode(img_bytes_for_api).decode()

        vision_text = user_prompt or (
            "Describe this image in detail. What do you see? "
            "If it looks AI-generated, digitally manipulated, or contains "
            "notable content (text, QR codes, faces, diagrams), mention it clearly."
        )

        vision_messages = [
            {"role": "system", "content": VENOM_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": vision_text},
                    {"type": "image_url",
                     "image_url": {"url": f"data:{mime};base64,{img_b64}"}}
                ],
            },
        ]

        # Try each vision model in order
        groq_key = _get_groq_key()
        if groq_key:
            for vmodel in _GROQ_VISION_MODELS:
                try:
                    with _call_groq_sync(vision_messages, model=vmodel) as resp:
                        data = json.loads(resp.read())
                        ai_analysis = data["choices"][0]["message"]["content"]
                    logger.info(f"[Vision] OK — model={vmodel}, file={req.file_name}")
                    break
                except Exception as ve:
                    logger.warning(f"[Vision] {vmodel} failed: {ve}")
                    continue

        # ── Fallback: local heuristics + text model ────────────────────────────
        if not ai_analysis:
            hints = []
            try:
                from PIL import Image as PILImage
                img = PILImage.open(io.BytesIO(file_bytes))
                exif = img._getexif() if hasattr(img, "_getexif") else None
                hints.append(f"Format: {img.format}, Size: {img.width}×{img.height}px, {file_size:,} bytes")
                if not exif:
                    hints.append("No EXIF metadata — likely AI-generated, screenshot, or metadata stripped")
                else:
                    from PIL.ExifTags import TAGS
                    exif_map = {TAGS.get(k, k): str(v)[:80] for k, v in exif.items()}
                    if "Software" in exif_map:
                        hints.append(f"Editing software: {exif_map['Software']}")
                    if "Make" in exif_map:
                        hints.append(f"Camera: {exif_map.get('Make','')} {exif_map.get('Model','')}")
            except Exception as pe:
                hints.append(f"Image file: {req.file_name}, {file_size:,} bytes")

            fallback_text = (
                f"The user uploaded an image: {req.file_name}\n"
                f"Local analysis: {'; '.join(hints)}\n"
                f"User request: {user_prompt or 'Describe and analyze this image.'}\n\n"
                "Note: Direct image viewing (vision AI) is temporarily unavailable. "
                "Based on the metadata above, provide what analysis you can."
            )
            fb_messages = [
                {"role": "system", "content": VENOM_SYSTEM_PROMPT},
                {"role": "user", "content": fallback_text},
            ]
            try:
                if _is_ollama_running():
                    ai_analysis = _call_ollama_sync(fb_messages)
                else:
                    gk = _get_groq_key()
                    if gk:
                        with _call_groq_sync(fb_messages) as resp:
                            data = json.loads(resp.read())
                            ai_analysis = data["choices"][0]["message"]["content"]
            except Exception as fe:
                ai_analysis = (
                    f"**Image received:** {req.file_name} ({file_size:,} bytes)\n\n"
                    f"Local hints: {'; '.join(hints)}\n\n"
                    f"Vision AI unavailable: {fe}"
                )

    # ══════════════════════════════════════════════════════════════════════════
    # PATH B — DOCUMENTS / PDFs → Extract text, then discuss
    # ══════════════════════════════════════════════════════════════════════════
    elif req.file_type == "document" and file_bytes:
        doc_text  = ""
        doc_note  = ""
        try:
            if req.file_name.lower().endswith(".pdf"):
                try:
                    import PyPDF2
                    pdf_reader = PyPDF2.PdfReader(io.BytesIO(file_bytes))
                    n_pages    = len(pdf_reader.pages)
                    read_up_to = min(n_pages, 15)
                    for pg in pdf_reader.pages[:read_up_to]:
                        doc_text += pg.extract_text() or ""
                    doc_note = f"PDF · {n_pages} pages · extracted {read_up_to}"
                except ImportError:
                    doc_text = file_bytes.decode("utf-8", errors="replace")[:8000]
                    doc_note = "PDF (PyPDF2 not installed — raw decode)"
            else:
                doc_text = file_bytes.decode("utf-8", errors="replace")[:8000]
                doc_note = f"Text file · {len(doc_text):,} chars"
        except Exception as de:
            doc_note = f"Extraction error: {de}"

        if not doc_text.strip():
            doc_text = "(No readable text extracted)"

        doc_prompt = user_prompt or "Please summarize this document and highlight the key points."

        # Scan for secrets in the extracted text
        import re as _re
        secret_patterns = [
            (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*\S{15,}", "API Key"),
            (r"(?i)(password|passwd)\s*[=:]\s*\S{6,}", "Password"),
            (r"eyJ[A-Za-z0-9_\-]{15,}\.eyJ[A-Za-z0-9_\-]{15,}", "JWT Token"),
            (r"(?i)ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
            (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key"),
        ]
        secrets_found = [label for pattern, label in secret_patterns
                         if _re.search(pattern, doc_text)]

        secret_note = (
            f"\n\n⚠️ **Security Notice:** The document contains potential secrets: "
            + ", ".join(secrets_found) if secrets_found else ""
        )

        doc_messages = [
            {"role": "system", "content": VENOM_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"The user uploaded a document: **{req.file_name}** ({doc_note})\n\n"
                    f"--- DOCUMENT CONTENT ---\n{doc_text[:6000]}\n--- END ---\n\n"
                    f"User's request: {doc_prompt}"
                ),
            },
        ]
        try:
            if _is_ollama_running():
                ai_analysis = _call_ollama_sync(doc_messages)
            else:
                gk = _get_groq_key()
                if gk:
                    with _call_groq_sync(doc_messages) as resp:
                        data = json.loads(resp.read())
                        ai_analysis = data["choices"][0]["message"]["content"]
        except Exception as de2:
            ai_analysis = f"Document analysis error: {de2}"

        if secret_note:
            ai_analysis = ai_analysis + secret_note

    # ══════════════════════════════════════════════════════════════════════════
    # PATH C — Other file types (video, etc.)
    # ══════════════════════════════════════════════════════════════════════════
    else:
        other_prompt = (
            f"The user uploaded a file: {req.file_name} "
            f"(type: {req.file_type}, size: {file_size:,} bytes). "
            + (f"They said: {user_prompt}" if user_prompt else
               "They haven't asked anything yet. Tell them what you can help with for this file.")
        )
        other_messages = [
            {"role": "system", "content": VENOM_SYSTEM_PROMPT},
            {"role": "user", "content": other_prompt},
        ]
        try:
            if _is_ollama_running():
                ai_analysis = _call_ollama_sync(other_messages)
            else:
                gk = _get_groq_key()
                if gk:
                    with _call_groq_sync(other_messages) as resp:
                        data = json.loads(resp.read())
                        ai_analysis = data["choices"][0]["message"]["content"]
        except Exception as oe:
            ai_analysis = f"File received: {req.file_name}. {oe}"

    if not ai_analysis:
        ai_analysis = (
            f"File received: **{req.file_name}** ({file_size:,} bytes). "
            "The AI backend is not reachable right now — please start Ollama or check your Groq API key."
        )

    # ── Save to session ────────────────────────────────────────────────────────
    history.append({"role": "user",      "content": f"[File: {req.file_name}] {user_prompt}"})
    history.append({"role": "assistant", "content": ai_analysis})
    trimmed = history[-40:]
    _sessions[session_id] = trimmed
    _save_session(session_id, trimmed)

    return {"ai_analysis": ai_analysis, "session_id": session_id}


# ── Offline message ────────────────────────────────────────────────────────────

def _offline_message() -> str:
    return (
        "**VENOM AI — AI Engine Not Configured**\n\n"
        "No AI backend is running. Start Ollama or configure an AI API key:\n\n"
        "```\n"
        "1. Install Ollama (free, local): https://ollama.ai\n"
        "2. Run: ollama pull llama3\n"
        "3. Restart: docker-compose restart api\n"
        "```"
    )