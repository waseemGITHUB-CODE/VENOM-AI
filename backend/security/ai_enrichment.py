"""
VENOM AI — AI Finding Enrichment (Phase 2d)
─────────────────────────────────────────────────────────────────────────
For each Finding produced by the attack engines, Groq generates:

  1. ai_explanation   — plain-English explanation a non-security person understands
  2. ai_code_fix      — actual code snippet that fixes the vulnerability
  3. ai_fix_language  — what language/framework the fix is for

The fix is tailored to the detected tech stack (Django, Express, Laravel, etc.)
so users get a working snippet, not generic advice.

Calls are made in PARALLEL (batched 5 at a time) to keep total enrichment
time under ~15 seconds even with 30 findings. If Groq is rate-limited or
unavailable, we fall back to deterministic templated advice — the finding
still gets explained, just not as elegantly.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger("venom.ai_enrich")


# ─── Tech-stack-aware fix templates (fallback when AI unavailable) ───────────
# Used to give SOMETHING useful even without LLM. Keyed by (owasp, tech).
_FALLBACK_FIXES = {
    ("A05", "python"): """# Use parameterized queries — never concatenate user input into SQL
from sqlalchemy import text
result = db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})""",
    ("A05", "javascript"): """// Use parameterized queries with placeholders
const result = await db.query("SELECT * FROM users WHERE email = ?", [email]);""",
    ("A05", "php"): """// Use PDO prepared statements
$stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
$stmt->execute(["email" => $email]);""",
}


# ─── Tech-stack detection helper ────────────────────────────────────────────
def _detect_primary_language(tech_summary: dict) -> str:
    """Best-effort guess at the primary backend language for code fixes."""
    if not tech_summary:
        return "generic"
    # Group everything detected
    all_names = []
    for cat, items in (tech_summary or {}).items():
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict):
                    all_names.append((it.get("name") or "").lower())
                else:
                    all_names.append(str(it).lower())
    text = " ".join(all_names)
    if any(k in text for k in ("django", "flask", "fastapi", "python")): return "python"
    if any(k in text for k in ("express", "node", "next.js", "nuxt")):   return "javascript"
    if any(k in text for k in ("rails", "ruby")):                          return "ruby"
    if any(k in text for k in ("laravel", "php")):                         return "php"
    if any(k in text for k in ("spring", "java")):                         return "java"
    if any(k in text for k in ("asp.net", ".net")):                        return "csharp"
    if any(k in text for k in ("go", "gin", "fiber")):                     return "go"
    return "generic"


# ─── Groq API client (lazy, with key rotation) ──────────────────────────────
_groq_clients_lock = threading.Lock()
_groq_keys: List[str] = []


def _get_groq_keys() -> List[str]:
    global _groq_keys
    with _groq_clients_lock:
        if _groq_keys:
            return _groq_keys
        keys = []
        for var in ("GROQ_API_KEY", "GROQ_API_KEY_2", "GROQ_API_KEY_3", "GROQ_API_KEY_4"):
            k = os.getenv(var, "").strip()
            if k and not k.startswith("PASTE_") and not k.startswith("your-"):
                keys.append(k)
        _groq_keys = keys
        return keys


def _groq_complete(prompt: str, max_tokens: int = 800) -> Optional[str]:
    """Single Groq call with key rotation on rate-limit. Returns text or None."""
    try:
        from groq import Groq
    except ImportError:
        return None
    keys = _get_groq_keys()
    if not keys:
        return None
    model = os.getenv("GROQ_MODEL_FAST") or os.getenv("GROQ_MODEL") or "llama-3.1-8b-instant"
    last_err = None
    for key in keys:
        try:
            client = Groq(api_key=key)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a senior application security engineer. Output ONLY valid JSON, no markdown."},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=max_tokens,
                temperature=0.3,
                response_format={"type": "json_object"},
            )
            text = (resp.choices[0].message.content or "").strip()
            return text
        except Exception as e:
            err = str(e)
            last_err = e
            if "rate_limit" in err.lower() or "429" in err:
                continue
            logger.warning(f"[AI Enrich] Groq error: {err[:120]}")
            return None
    logger.warning(f"[AI Enrich] All keys exhausted: {last_err}")
    return None


# ─── Single-finding enrichment prompt ───────────────────────────────────────
def _build_enrich_prompt(finding: dict, primary_lang: str, target_url: str) -> str:
    """Build a compact prompt asking for explanation + code fix."""
    return f"""A vulnerability was found in a target application during a security scan. Produce a clear plain-English explanation and a working code fix.

TARGET:           {target_url}
PRIMARY LANGUAGE: {primary_lang}

FINDING:
  Title:          {finding.get('title', '')}
  OWASP category: {finding.get('owasp', '')}
  CWE:            {finding.get('cwe_id', '')}
  Severity:       {finding.get('severity', '')}
  Affected URL:   {finding.get('affected_url', '')[:200]}
  Parameter:      {finding.get('parameter', '')}
  Payload used:   {(finding.get('payload') or '')[:200]}
  Evidence:       {(finding.get('evidence') or '')[:300]}
  Description:    {(finding.get('description') or '')[:400]}

Respond with VALID JSON ONLY in this exact schema:
{{
  "ai_explanation": "<3-5 sentences. Explain to a non-security developer what this vulnerability is, WHY it is dangerous in plain English, and what an attacker could realistically do with it. Use the affected URL and parameter in your explanation so it feels specific to this finding, not generic.>",
  "ai_code_fix": "<Working code in {primary_lang} that fixes this specific vulnerability. Show the BEFORE and AFTER pattern as separate code blocks with comments. Include real library names and function signatures the developer will actually use. NO markdown fences - just the raw code.>",
  "ai_fix_language": "{primary_lang}"
}}

Be specific to the finding (mention the parameter, the payload, the URL). Avoid generic boilerplate. Keep the code fix under 25 lines."""


def _enrich_single(finding: dict, primary_lang: str, target_url: str) -> dict:
    """Enrich one finding. Returns dict {ai_explanation, ai_code_fix, ai_fix_language}."""
    prompt = _build_enrich_prompt(finding, primary_lang, target_url)
    raw = _groq_complete(prompt, max_tokens=900)
    if raw:
        # Strip optional markdown fences
        if raw.startswith("```"):
            raw = raw.split("```", 2)[1]
            if raw.lower().startswith("json"):
                raw = raw[4:].strip()
            raw = raw.split("```", 1)[0]
        try:
            parsed = json.loads(raw)
            return {
                "ai_explanation":  str(parsed.get("ai_explanation") or "")[:3000],
                "ai_code_fix":     str(parsed.get("ai_code_fix") or "")[:4000],
                "ai_fix_language": (parsed.get("ai_fix_language") or primary_lang)[:40],
            }
        except Exception as e:
            logger.debug(f"[AI Enrich] JSON parse failed: {e}. Raw: {raw[:200]}")

    # Fallback — deterministic template
    fallback_code = _FALLBACK_FIXES.get((finding.get("owasp"), primary_lang), "")
    return {
        "ai_explanation": (
            f"This is a {finding.get('severity', 'medium')}-severity "
            f"{finding.get('title', 'security issue')} found at "
            f"{finding.get('affected_url') or 'the target'}. "
            f"{finding.get('description') or 'See description for details.'} "
            f"An attacker could exploit this to compromise the application. "
            f"Apply the recommended fix immediately."
        )[:3000],
        "ai_code_fix": fallback_code or (finding.get("recommendation") or "")[:4000],
        "ai_fix_language": primary_lang,
    }


# ─── Public API ──────────────────────────────────────────────────────────────

def enrich_findings(findings: List[dict], target_url: str = "",
                     tech_summary: Optional[dict] = None,
                     max_workers: int = 5) -> List[dict]:
    """
    Enrich every finding with ai_explanation + ai_code_fix + ai_fix_language.
    Modifies findings in place AND returns the list.

    Uses a thread pool to run up to `max_workers` Groq calls in parallel.
    Total time is roughly: ceil(len(findings)/max_workers) * ~3s per call.
    """
    if not findings:
        return findings
    primary_lang = _detect_primary_language(tech_summary or {})
    logger.info(f"[AI Enrich] Enriching {len(findings)} findings, primary_lang={primary_lang}")

    start = time.monotonic()
    keys_available = bool(_get_groq_keys())
    if not keys_available:
        logger.warning("[AI Enrich] No Groq keys — using deterministic fallback only")

    def _process(f):
        try:
            enrichment = _enrich_single(f, primary_lang, target_url)
            f["ai_explanation"]  = enrichment["ai_explanation"]
            f["ai_code_fix"]     = enrichment["ai_code_fix"]
            f["ai_fix_language"] = enrichment["ai_fix_language"]
            f["ai_enriched_at"]  = datetime.utcnow()
        except Exception as e:
            logger.warning(f"[AI Enrich] Single-finding enrichment failed: {e}")
        return f

    if keys_available:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            list(ex.map(_process, findings))
    else:
        for f in findings:
            _process(f)

    logger.info(f"[AI Enrich] Done in {time.monotonic() - start:.1f}s")
    return findings
