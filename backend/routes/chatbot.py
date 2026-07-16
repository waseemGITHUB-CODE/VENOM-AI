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

# Tavily — accurate AI-optimized web search. When TAVILY_API_KEY is set it is used
# as the PRIMARY search source (with a direct answer + ranked results). Otherwise
# VENOM uses SearXNG — a free, self-hosted metasearch engine with no API key and
# no rate limit (see docker-compose.yml) — then finally the free Google News /
# HackerNews / Wikipedia sources if even that isn't reachable.
TAVILY_API_KEY = os.getenv("TAVILY_API_KEY", "").strip()
TAVILY_URL     = "https://api.tavily.com/search"
SEARXNG_URL    = os.getenv("SEARXNG_URL", "http://searxng:8080").rstrip("/")

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
• THE USER'S OWN VENOM ACTIVITY — their scans, findings, targets, reports, security
  score, and what they've done in the VENOM platform. Questions like "what have we
  done recently", "what did the last scan find", "which target did I scan", "what
  are the recent scans", "summarize my findings" are IN SCOPE. Answer them using the
  VENOM CONTEXT block provided below. If the context has no scan data, say so plainly
  ("I don't see any recent scans yet — run one and I'll summarize it") — never refuse
  these as off-topic.

OFF-TOPIC REFUSAL:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ONLY refuse questions that are genuinely unrelated to security or the user's VENOM work
— food, recipes, movies, relationships, sports, creative writing, etc. Do NOT refuse
questions about the user's scans, findings, or what VENOM is doing.

NEVER treat a message as off-topic just because it contains a loaded word like "hack",
"attack", or "exploit", or because it's short/vague ("one hack to try", "show me an
example", "give me one"). Students, learners, and CTF players asking for a technique,
an example exploit, or "something to demo" are asking an on-topic, answerable question
— engage with it directly (e.g. point them at a legal practice target like OWASP Juice
Shop / DVWA / a VENOM demo target, and walk through a real technique). Do NOT respond
with a bare, generic "I can't help with that" to anything in your scope above — that
is a failure to follow these instructions, not a safety measure.

When something is truly off-topic (recipes, movies, etc.), decline briefly but NEVER
repeat the exact same refusal sentence twice in one conversation — vary the wording
each time, e.g.:
- "That's outside what I cover — I'm built for security and technical work. Got a scan, a CVE, or a technique you want to dig into?"
- "Not really my lane — I'm VENOM's security specialist. Ask me about vulnerabilities, exploits, or your scan results instead."
- "I'll stay in my area: cybersecurity and technical topics. Happy to help if you've got something security-related."

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

PERSONA — a warm, friendly, and capable AI teammate (think a relaxed, sharp security buddy):
• Friendly and natural, not stiff or robotic. Confident but easy-going.
• Talk like a helpful human teammate — conversational, brief, and real. Casual acknowledgements are good ("Sure", "Got it", "On it", "Nice").
• Never use emojis, markdown, bullet points, headings, code fences, or symbols — your text is SPOKEN. Plain, natural spoken sentences only.
• No robotic filler, no "how can I help" on a loop, no apologies unless a real error occurred. Never exaggerate or pretend.

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

def _tavily_search(query: str, max_results: int = 5) -> list:
    """Accurate AI-optimized web search via Tavily. Returns [{title,url,snippet}].
    Includes Tavily's direct 'answer' as the first item for grounding."""
    import urllib.request, json as _json
    payload = _json.dumps({
        "query": query,
        "search_depth": "basic",       # "advanced" = deeper but uses more credits
        "max_results": max_results,
        "include_answer": True,
    }).encode()
    req = urllib.request.Request(
        TAVILY_URL, data=payload, method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {TAVILY_API_KEY}"},
    )
    with urllib.request.urlopen(req, timeout=12) as r:
        data = _json.loads(r.read().decode())
    out = []
    ans = (data.get("answer") or "").strip()
    if ans:
        out.append({"title": "Direct answer (Tavily)", "url": "", "snippet": ans})
    for item in (data.get("results") or [])[:max_results]:
        title = (item.get("title") or "").strip()
        if not title:
            continue
        out.append({
            "title":   title[:140],
            "url":     item.get("url", ""),
            "snippet": (item.get("content") or "").strip()[:320],
        })
    return out


def _searxng_search(query: str, max_results: int = 5) -> list:
    """Free, self-hosted web search via SearXNG — no API key, no rate limit.
    Returns [{title,url,snippet}]."""
    import urllib.request, urllib.parse, json as _json
    url = f"{SEARXNG_URL}/search?" + urllib.parse.urlencode({
        "q": query, "format": "json", "safesearch": "1",
    })
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; VENOM-AI/2.0)"}
    )
    with urllib.request.urlopen(req, timeout=8) as r:
        data = _json.loads(r.read().decode())
    out = []
    for item in (data.get("results") or [])[:max_results]:
        title = (item.get("title") or "").strip()
        if not title:
            continue
        out.append({
            "title":   title[:140],
            "url":     item.get("url", ""),
            "snippet": (item.get("content") or "").strip()[:320],
        })
    return out


def _web_search(query: str, max_results: int = 5) -> list:
    """
    Live search. Tavily first (accurate) when a key is set, then SearXNG
    (free, self-hosted, no key needed), then the free Google News /
    HackerNews / Wikipedia sources as a last-resort fallback.
    """
    import urllib.request, urllib.parse, json as _json

    # ── Source 0: Tavily (primary, when configured) ──
    if TAVILY_API_KEY:
        try:
            tav = _tavily_search(query, max_results)
            if tav:
                logger.info(f"[WebSearch] Tavily → {len(tav)} results for '{query[:50]}'")
                return tav
        except Exception as e:
            logger.warning(f"[WebSearch] Tavily failed ({e}) — trying SearXNG")

    # ── Source 0.5: SearXNG (free, self-hosted, no key) ──
    try:
        sx = _searxng_search(query, max_results)
        if sx:
            logger.info(f"[WebSearch] SearXNG → {len(sx)} results for '{query[:50]}'")
            return sx
    except Exception as e:
        logger.debug(f"[WebSearch] SearXNG unavailable ({e}) — falling back to free scraping sources")

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
    """Collect all configured Groq keys from env.

    Accepts GROQ_API_KEY (primary) and GROQ_API_KEY_1..._4. GROQ_API_KEY and
    GROQ_API_KEY_1 are aliases for the first key, so either name works.
    Duplicate key values are collapsed.
    """
    keys = []
    for suffix in ["", "_1", "_2", "_3", "_4"]:
        k = os.getenv(f"GROQ_API_KEY{suffix}", "").strip()
        if k and k not in keys:
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

def _get_available_groq_key() -> str:
    """Return a Groq key only if it is currently out of cooldown."""
    keys = _all_groq_keys()
    if not keys:
        return ""
    now = _time.time()
    with _groq_key_lock:
        for offset in range(len(keys)):
            idx = (_groq_key_index + offset) % len(keys)
            if now >= _groq_key_cooldowns.get(idx, 0):
                return keys[idx]
    return ""

def _seconds_until_next_groq_key() -> int:
    """How long until any Groq key leaves cooldown."""
    keys = _all_groq_keys()
    if not keys:
        return 0
    now = _time.time()
    waits = []
    with _groq_key_lock:
        for idx in range(len(keys)):
            cooldown_until = _groq_key_cooldowns.get(idx, 0)
            if now >= cooldown_until:
                return 0
            waits.append(max(1, int(cooldown_until - now) + 1))
    return min(waits) if waits else 0

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
    Use the powerful model for anything technical/security-flavored (even short
    messages — the small fast model is more prone to ignoring VENOM's system
    prompt and falling back to its own built-in generic refusal on words like
    "hack"), and the fast 8B model only for genuinely simple/casual chit-chat.
    """
    fast_model = os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b")
    full_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    m = message.strip().lower()

    # Technical/security keywords → always use the full model, regardless of
    # message length. Checked BEFORE the short-message shortcut below, since a
    # short message like "explain xss" or "one hack to try" is exactly the
    # case where the small model tends to over-refuse.
    _HEAVY = [
        "exploit", "vulnerability", "cve", "payload", "injection", "xss", "sqli",
        "malware", "ransomware", "pentest", "reverse shell", "privilege", "bypass",
        "shellcode", "buffer overflow", "forensic", "osint", "phishing", "c2",
        "scan", "security", "hack", "hacking", "hacked", "crack", "cracking",
        "keylogger", "trojan", "rootkit", "backdoor", "brute force", "bruteforce",
        "spoof", "sniff", "wifi", "vpn", "tor", "breach", "ddos", "botnet",
        "attack", "firewall", "encrypt", "decrypt",
        "code", "python", "javascript", "function", "algorithm", "database", "sql",
        "explain", "how does", "what is", "difference between", "compare",
        "analyze", "review", "generate", "write", "create", "implement",
    ]
    if any(kw in m for kw in _HEAVY):
        return full_model

    # Everything else (short casual chit-chat, or longer messages with no
    # technical keyword hit) → fast model
    return fast_model

def _groq_model_candidates(message: str) -> list[str]:
    """Preferred model first, then the lighter fast model as a reliability fallback."""
    chosen = _pick_groq_model(message)
    fast   = os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b")
    return [chosen] if chosen == fast else [chosen, fast]

# Generic canned refusals the small/fast model sometimes emits on its own
# (ignoring VENOM's system prompt), independent of what the message was about.
# Kept short and literal on purpose — this only matches the boilerplate
# "can't help" phrasing itself, not real declines that engage with the topic.
_GENERIC_REFUSAL_RE = _re.compile(
    r"^\s*(i'?m|i am)\s+sorry,?\s+(but\s+)?i\s+(can'?t|cannot|am unable to|won'?t)\s+"
    r"(help|assist)\b.{0,40}$",
    _re.IGNORECASE,
)

def _is_generic_refusal(text: str) -> bool:
    """True if the reply is (or starts with) a short, boilerplate refusal that
    didn't actually engage with the question — a sign the small model ignored
    the system prompt rather than a deliberate on-topic decline."""
    if not text:
        return False
    return bool(_GENERIC_REFUSAL_RE.match(text.strip()))

def _is_rate_limited_error(err: Exception | None) -> bool:
    if not err:
        return False
    s = str(err).lower()
    return (
        "429" in s or
        "rate limit" in s or
        "rate-limited" in s or
        "too many requests" in s or
        "cooling down" in s
    )


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
    msgs.extend(_bounded_history(history, max_messages=20, max_chars=9000))
    msgs.append({"role": "user", "content": user_message})
    return msgs


def _bounded_history(history: List[dict], max_messages: int = 20, max_chars: int = 9000) -> List[dict]:
    """
    Cap conversation history by BOTH message count and total character budget.
    A single long AI reply (tables, code, CVE lists — we've seen several KB each)
    can otherwise make the request grow unbounded across a long session, which
    triggers Groq's 413 Payload Too Large and then a slow Ollama fallback that
    hangs for the full timeout on the oversized context. Walk backward from the
    most recent turns and stop once the char budget is spent.
    """
    recent = history[-max_messages:]
    out, total = [], 0
    for msg in reversed(recent):
        content = msg.get("content", "") or ""
        total += len(content)
        if total > max_chars and out:
            break   # keep at least the most recent turn even if it alone is huge
        out.append(msg)
    return list(reversed(out))


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
    """Stream from Ollama /api/chat endpoint.
    Timeout kept short (was 120s) — this only runs as a FALLBACK after Groq has
    already failed, so a slow/stuck local model must not freeze the whole app
    (the underlying urllib call is blocking and would otherwise stall FastAPI's
    event loop for the full timeout — callers should run this via asyncio.to_thread)."""
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
    return urllib.request.urlopen(req, timeout=30)


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
    with urllib.request.urlopen(req, timeout=30) as r:
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

    attempted_keys = set()

    for attempt in range(len(keys)):   # try each currently-available key at most once
        api_key = _get_available_groq_key()
        if not api_key or api_key in attempted_keys:
            break
        attempted_keys.add(api_key)

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

    retry_after = _seconds_until_next_groq_key()
    if retry_after > 0:
        raise RuntimeError(f"All Groq API keys are cooling down. Retry in about {retry_after}s.")
    raise last_error or RuntimeError("All Groq API keys are rate-limited. Try again shortly.")


def _call_groq_text(messages: List[dict], model: str) -> str:
    """Convenience helper for a standard non-streaming Groq text completion."""
    with _call_groq_sync(messages, model=model) as r:
        data = json.loads(r.read().decode())
    return data.get("choices", [{}])[0].get("message", {}).get("content") or ""


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


def _venom_live_context(user) -> str:
    """Query the user's REAL scans so the chatbot can answer 'recent scans',
    'what's running', 'dashboard status' from live data — not just browser state."""
    if user is None:
        return ""
    try:
        from db.database import SessionLocal
        from db.models import AttackScan
        db = SessionLocal()
        try:
            scans = (db.query(AttackScan)
                     .filter(AttackScan.owner_id == user.id)
                     .order_by(AttackScan.id.desc()).limit(8).all())
            if not scans:
                return "VENOM LIVE DATA: The user has NO scans yet. Suggest running one."
            def _st(s):
                v = getattr(s.status, "value", s.status)
                return str(v).lower()
            running = [s for s in scans if _st(s) in ("running", "queued", "pending", "scanning", "in_progress")]
            lines = ["VENOM LIVE DATA — the user's ACTUAL scans (use this to answer anything about their "
                     "recent scans, running scans, findings, or dashboard):"]
            lines.append(f"Currently running: {len(running)} scan(s)" +
                         ("" if not running else " — " + ", ".join(f"{s.target_url} ({_st(s)})" for s in running)))
            lines.append("Recent scans (newest first):")
            for s in scans:
                fc = getattr(s, "total_findings", None)
                sc = getattr(s, "security_score", None)
                when = s.started_at.strftime("%Y-%m-%d %H:%M") if getattr(s, "started_at", None) else ""
                lines.append(f"  #{s.id} {s.target_url} — {_st(s)}"
                             + (f", {fc} findings" if fc is not None else "")
                             + (f", score {sc}/100" if sc else "")
                             + (f", {when}" if when else ""))
            return "\n".join(lines)
        finally:
            db.close()
    except Exception as e:
        logger.debug(f"[LiveContext] {e}")
        return ""


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
    live_ctx = _venom_live_context(current_user)
    msgs_base = _build_messages(history, req.message, req.context, voice=getattr(req,'voice',False))
    extra_sys = []
    if live_ctx:
        extra_sys.append({"role": "system", "content": live_ctx})
    if kb_ctx:
        extra_sys.append({"role": "system", "content": kb_ctx})
    if search_ctx:
        extra_sys.append({"role": "system", "content": search_ctx})
    messages = [msgs_base[0]] + extra_sys + msgs_base[1:]
    reply      = ""
    model_used = ""
    groq_error = None

    # ── Groq FIRST (fast, primary) — auto-rotates keys + smart model ──
    if _get_groq_key():
        model_candidates = _groq_model_candidates(req.message)
        full_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
        if full_model not in model_candidates:
            # Emergency retry target: if the chosen (small) model comes back with
            # a boilerplate refusal instead of engaging, try the smarter model
            # once before giving up — it's much less prone to that.
            model_candidates = model_candidates + [full_model]
        for idx, chosen_model in enumerate(model_candidates):
            try:
                reply = _call_groq_text(messages, chosen_model)
                if not reply:
                    raise RuntimeError("Groq returned an empty response.")
                if _is_generic_refusal(reply) and idx < len(model_candidates) - 1:
                    logger.warning(
                        f"[Chat] Groq model '{chosen_model}' gave a generic refusal — "
                        f"retrying with '{model_candidates[idx + 1]}'"
                    )
                    reply = ""
                    continue
                model_used = f"groq/{chosen_model}"
                logger.info(f"[Chat] Groq response: session={session_id} model={chosen_model}")
                break
            except Exception as e:
                groq_error = e
                if idx < len(model_candidates) - 1:
                    logger.warning(f"[Chat] Groq model '{chosen_model}' failed: {e} — trying lighter fallback")
                    continue

    # ── Ollama FALLBACK — only when Groq is unavailable/rate-limited ──
    # (User's local Ollama keeps the chat working during Groq rate-limits.)
    if not reply and _is_ollama_running():
        try:
            # Run off the event loop — this is a blocking urllib call and would
            # otherwise freeze the ENTIRE API (all users, all endpoints) for up
            # to 30s if Ollama is slow.
            reply      = await _asyncio.to_thread(_call_ollama_sync, messages)
            model_used = f"ollama/{OLLAMA_MODEL}"
            logger.info(f"[Chat] Ollama fallback response: session={session_id} chars={len(reply)}")
        except Exception as e:
            logger.warning(f"[Chat] Ollama fallback failed: {e}")

    # ── Offline (nothing available) ──
    if not reply:
        if _is_rate_limited_error(groq_error):
            retry_after = _seconds_until_next_groq_key()
            wait_hint = f"Please wait about {retry_after} seconds and try again." if retry_after else "Please wait a few seconds and try again."
            reply = ("⚡ **VENOM AI is experiencing high demand right now.**\n\n"
                     f"All AI servers are temporarily busy. {wait_hint}")
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

    # Build messages with live scan data + search + KB context
    live_ctx = _venom_live_context(current_user)
    msgs_base = _build_messages(history, req.message, req.context, voice=getattr(req,'voice',False))
    extra_sys = []
    if live_ctx:
        extra_sys.append({"role": "system", "content": live_ctx})
    if kb_ctx:
        extra_sys.append({"role": "system", "content": kb_ctx})
    if search_ctx:
        extra_sys.append({"role": "system", "content": search_ctx})
    # Insert extra context right after the system prompt
    messages = [msgs_base[0]] + extra_sys + msgs_base[1:]

    # ────────────────────────────────────────────────────────────────
    # PATH A — Ollama streaming — ONLY when no Groq key is configured.
    # (When Groq IS configured, Groq is primary and Ollama is used as an
    #  in-stream fallback inside groq_gen when Groq is rate-limited.)
    # ────────────────────────────────────────────────────────────────
    if not _get_groq_key() and _is_ollama_running():
        accumulated = []

        async def ollama_gen():
            try:
                # Open off the event loop — this blocking call is where the real
                # wait happens (connecting + model warm-up); once the stream is
                # flowing, per-chunk reads are fast enough not to matter.
                resp = await _asyncio.to_thread(_call_ollama_stream, messages)
                with resp:
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
        model_candidates = _groq_model_candidates(req.message)
        _full_model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
        if _full_model not in model_candidates:
            model_candidates = model_candidates + [_full_model]
        chosen_model = model_candidates[0]
        accumulated  = []

        async def groq_gen():
            # Open the Groq stream, falling back to the fast 8B model if the chosen
            # model fails to connect (bad key already handled by key-rotation; this
            # covers decommissioned models / oversized context / transient 5xx).
            # Retrying at OPEN time preserves real-time token streaming.
            resp, last_err = None, None
            for idx, mdl in enumerate(model_candidates):
                try:
                    resp = _call_groq_sync(messages, stream=True, model=mdl)
                    last_err = None
                    break
                except Exception as e:
                    last_err = e
                    if idx < len(model_candidates) - 1:
                        if _is_rate_limited_error(e):
                            logger.warning(f"[Chat] Groq model '{mdl}' is busy — trying lighter fallback")
                        else:
                            logger.warning(f"[Chat] Groq open failed on '{mdl}': {e} — trying fallback")
                        continue
                    logger.warning(f"[Chat] Groq stream open failed on '{mdl}': {e}")

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
                # Streaming can fail even when a normal completion would still work.
                # Try one last non-stream fallback before surfacing an error bubble.
                fallback_text = ""
                for idx, mdl in enumerate(model_candidates):
                    try:
                        fallback_text = _call_groq_text(messages, mdl)
                        if fallback_text:
                            accumulated.append(fallback_text)
                            for i in range(0, len(fallback_text), 120):
                                chunk = json.dumps({"choices": [{"delta": {"content": fallback_text[i:i+120]}}]})
                                yield f"data: {chunk}\n\n"
                            last_err = None
                            break
                    except Exception as e:
                        last_err = e
                        if idx < len(model_candidates) - 1:
                            logger.warning(f"[Chat] Groq non-stream fallback failed on '{mdl}': {e} — trying fallback")

            # ── Groq exhausted/rate-limited → fall back to LOCAL OLLAMA so the
            #    user can keep working (streams tokens live, same web context). ──
            if last_err is not None and not accumulated and _is_ollama_running():
                try:
                    oresp = await _asyncio.to_thread(_call_ollama_stream, messages)
                    with oresp:
                        for raw in oresp:
                            line = raw.decode("utf-8").strip()
                            if not line:
                                continue
                            try:
                                chunk = json.loads(line)
                                token = chunk.get("message", {}).get("content", "")
                                if token:
                                    accumulated.append(token)
                                    sse = json.dumps({"choices": [{"delta": {"content": token}}]})
                                    yield f"data: {sse}\n\n"
                                if chunk.get("done"):
                                    break
                            except json.JSONDecodeError:
                                pass
                    if accumulated:
                        last_err = None
                        logger.info("[Chat] Fell back to local Ollama (Groq was rate-limited)")
                except Exception as e:
                    logger.warning(f"[Chat] Ollama stream fallback failed: {e}")

            if last_err is not None and not accumulated:
                if _is_rate_limited_error(last_err):
                    retry_after = _seconds_until_next_groq_key()
                    wait_hint = f"Please wait about {retry_after} seconds and try again." if retry_after else "Please wait a few seconds and try again."
                    friendly = (
                        "⚡ **VENOM AI is experiencing high demand right now.**\n\n"
                        f"All AI servers are temporarily busy. {wait_hint}"
                    )
                else:
                    friendly = (
                        "⚠️ **AI response failed.** Please try sending your message again.\n\n"
                        f"_If the issue persists, try refreshing the page._"
                    )
                accumulated.append(friendly)
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


# ════════════════════════════════════════════════════════════════════════════
#  AGENT MODE — VENOM executes actions via tool-calling (not just chat)
#  The LLM chooses tools; the FRONTEND executes them against the real UI and
#  reports success/failure. VENOM confirms only after real execution.
# ════════════════════════════════════════════════════════════════════════════

# Tool schema (OpenAI/Groq function-calling format). These are IN-APP actions
# the frontend executor knows how to run.
VENOM_TOOLS = [
    {"type": "function", "function": {
        "name": "navigate",
        "description": "Open/switch to a page inside the VENOM app.",
        "parameters": {"type": "object", "properties": {
            "page": {"type": "string", "enum": [
                "dashboard", "scanner", "nhi", "attack-graph", "monitoring",
                "threat", "reports", "chat", "about", "compliance"]}},
            "required": ["page"]}}},
    {"type": "function", "function": {
        "name": "start_owasp_scan",
        "description": "Launch an active OWASP Top 10:2025 vulnerability scan against a target URL. Navigates to the scanner and starts it.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string", "description": "Full target URL, e.g. http://example.com"}},
            "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "start_nhi_scan",
        "description": "Launch an NHI secret/credential scan (scans a site's JS for leaked secrets) against a target URL.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "analyze_website",
        "description": "Autonomously assess a website end-to-end: recon, OWASP scan, analysis, and report. Use when the user says 'analyze', 'assess', or 'pentest' a site.",
        "parameters": {"type": "object", "properties": {
            "url": {"type": "string"}}, "required": ["url"]}}},
    {"type": "function", "function": {
        "name": "gather_intel",
        "description": "Run a PASSIVE OSINT recon sweep on a domain to map its attack surface: subdomains, DNS + email posture (SPF/DMARC), WHOIS, tech stack, security headers, TLS, and archived URLs. Use for 'gather intel', 'recon', 'reconnaissance', 'attack surface', 'what can you find about X', 'profile this domain'. No attacks are sent.",
        "parameters": {"type": "object", "properties": {
            "domain": {"type": "string", "description": "Domain or URL, e.g. example.com"}},
            "required": ["domain"]}}},
    {"type": "function", "function": {
        "name": "read_scan_results",
        "description": "Read the findings from the most recent scan (counts, top vulnerabilities, risk).",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "generate_report",
        "description": "Generate/download a PDF report for the latest scan.",
        "parameters": {"type": "object", "properties": {}}}},
    {"type": "function", "function": {
        "name": "read_current_page",
        "description": "Report which VENOM page the user is currently viewing.",
        "parameters": {"type": "object", "properties": {}}}},
]

VENOM_AGENT_SYSTEM_PROMPT = """You are VENOM Voice — the autonomous AI Security Operations Officer that OPERATES the VENOM platform. You are not a chatbot; you are an operating layer that EXECUTES the user's requests using tools.

CORE RULE — EXECUTE, DON'T DESCRIBE:
If the user asks for an action VENOM can perform, you MUST call the matching tool. Never say you did something unless a tool performs it. Never fabricate navigation, scans, or results.

TOOLS YOU CONTROL:
- navigate(page): open a VENOM page (dashboard, scanner, nhi, attack-graph, monitoring, threat, reports, chat, about, compliance)
- start_owasp_scan(url): launch an active OWASP Top 10:2025 scan
- start_nhi_scan(url): launch a secret/credential scan
- analyze_website(url): autonomous full assessment (recon -> scan -> analyze -> report)
- gather_intel(domain): PASSIVE OSINT sweep — subdomains, DNS/email posture, WHOIS, tech, headers, TLS, archived URLs
- read_scan_results(): read the latest findings
- generate_report(): produce the PDF report
- read_current_page(): report the current page

HOW TO DECIDE:
- "open/go to/show <page>" -> navigate
- "scan/test <url>" -> start_owasp_scan (or start_nhi_scan for secrets)
- "analyze/assess/pentest <site>" -> analyze_website
- "gather intel / recon / attack surface / what can you find about <domain>" -> gather_intel
- "what did you find / results / findings" -> read_scan_results
- "make/generate/download report" -> generate_report
- A pure knowledge question (e.g. "what is SQL injection") -> DON'T call a tool; just answer briefly.
- If a scan/analyze request has no URL, ask for the target in one short sentence (no tool call).

STYLE (spoken aloud): warm, friendly, and natural — like a helpful human teammate, not a robot reading text. Conversational and BRIEF: usually one short sentence, sometimes just a few words. It's fine to be casual ("Sure, opening that now", "Got it", "On it", "Nice — that's done"). Occasionally acknowledge the user naturally. No emojis, no markdown, no symbols, no lists. Never guess — if unsure, say so briefly and casually.

You may call MULTIPLE tools if the request needs it (e.g. navigate then scan). The app executes them and reports success; keep any text you return short."""


def _call_groq_agent(messages, model):
    """Non-streaming Groq call WITH tools. Returns (content, tool_calls, model)."""
    import urllib.request, urllib.error
    keys = _all_groq_keys()
    if not keys:
        raise ValueError("No Groq API key configured.")
    last_error = None
    for _ in range(len(keys) + 1):
        api_key = _get_groq_key()
        if not api_key:
            break
        payload = json.dumps({
            "model": model, "messages": messages,
            "tools": VENOM_TOOLS, "tool_choice": "auto",
            "max_tokens": 1024, "temperature": 0.3,
        }).encode()
        req = urllib.request.Request(GROQ_URL, data=payload, method="POST", headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "Mozilla/5.0 (compatible; VENOM-AI/2.0)"})
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                data = json.loads(r.read().decode())
            msg = data.get("choices", [{}])[0].get("message", {})
            return msg.get("content") or "", msg.get("tool_calls") or [], model
        except urllib.error.HTTPError as e:
            if e.code == 429:
                _mark_groq_key_rate_limited(api_key, 60); last_error = e; continue
            last_error = e; break
        except Exception as e:
            last_error = e; break
    raise last_error or RuntimeError("Groq agent call failed")


class AgentRequest(BaseModel):
    session_id: Optional[str] = None
    message: str
    context: Optional[dict] = None
    voice: bool = True


@router.post("/agent")
async def chat_agent(req: AgentRequest,
                     current_user: Optional[_AuthUser] = Depends(get_optional_user)):
    """
    Agent turn: the LLM decides which VENOM tools to call. Returns:
      { speak: str, actions: [{tool, args}], session_id }
    The FRONTEND executes the actions and confirms to the user.
    """
    session_id = _scoped_session_id(req.session_id, current_user)
    history    = _load_session(session_id)

    # Build messages with the agent prompt + live context
    ctx_msgs = _build_messages(history, req.message, req.context, voice=req.voice)
    # Swap the system prompt for the agent (execute-first) prompt
    ctx_msgs[0] = {"role": "system", "content": VENOM_AGENT_SYSTEM_PROMPT}

    groq_key = _get_groq_key()
    if not groq_key:
        return {"speak": "AI engine is offline. Add a Groq API key to enable the agent.",
                "actions": [], "session_id": session_id}

    model = os.getenv("GROQ_MODEL_FAST", "openai/gpt-oss-20b")
    try:
        content, tool_calls, used = _call_groq_agent(ctx_msgs, model)
    except Exception as e:
        es = str(e).lower()
        logger.error(f"[Agent] Groq call failed: {e}")
        if "429" in es or "rate" in es or "too many" in es:
            msg = "Hang on, the AI servers are busy for a moment — try again in a few seconds."
        else:
            msg = "Sorry, I couldn't reach the AI just now — give it another try."
        return {"speak": msg, "actions": [], "session_id": session_id}

    actions = []
    for tc in tool_calls:
        fn = (tc.get("function") or {})
        name = fn.get("name")
        try:
            args = json.loads(fn.get("arguments") or "{}")
        except Exception:
            args = {}
        if name:
            actions.append({"tool": name, "args": args})

    # Persist the turn (store a compact record)
    history.append({"role": "user", "content": req.message})
    summary = content or ("[actions: " + ", ".join(a["tool"] for a in actions) + "]" if actions else "")
    history.append({"role": "assistant", "content": summary})
    trimmed = history[-40:]
    _sessions[session_id] = trimmed
    _save_session(session_id, trimmed)

    return {"speak": content or "", "actions": actions,
            "session_id": session_id, "model": f"groq/{used}"}


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
    # If keys ARE configured, this is a transient rate-limit — say so honestly
    # instead of the misleading "not configured".
    if _all_groq_keys():
        return (
            "⚡ **Give me a few seconds — the AI is busy right now.**\n\n"
            "The free AI servers are at capacity for a moment. Please try again shortly. "
            "If this keeps happening, your free quota is maxed out — add more API keys "
            "(from separate accounts) or run a local model for unlimited use."
        )
    return (
        "**VENOM AI — AI Engine Not Configured**\n\n"
        "No AI backend is set up yet. Add one:\n\n"
        "```\n"
        "1. Free Groq key: https://console.groq.com/keys  → paste into backend/.env\n"
        "2. Or local (unlimited): install Ollama (https://ollama.ai), run 'ollama pull llama3'\n"
        "3. Restart: docker compose up -d --force-recreate api\n"
        "```"
    )
