"""
VENOM AI — Phase 2b: AI-Driven Test Case Planner
─────────────────────────────────────────────────────────────────────────
Takes recon output and uses Groq LLM to produce a prioritized attack plan
specific to the target application.

Input  : ReconResult + DiscoveredEndpoints + DiscoveredForms + DetectedTech
Output : AttackPlan with per-endpoint test cases mapped to OWASP Top 10:2025

The planner:
  1. Summarizes recon data into a structured AI prompt
  2. Asks Groq to identify business logic flows (login, checkout, etc.)
  3. Asks Groq to pick which OWASP categories matter most for this stack
  4. Returns a structured JSON plan the attack engines (2c-2g) consume

We DO NOT rely on the AI for payloads themselves — payloads are deterministic
code in the attack engines. AI is used ONLY for prioritization and business
logic detection (where deterministic rules can't see the big picture).
"""
from __future__ import annotations

import json
import logging
import os
from typing import Optional, List, Dict
from datetime import datetime

logger = logging.getLogger("venom.ai_planner")


# ── OWASP Top 10:2025 reference for the AI prompt ──────────────────────────
OWASP_2025_REF = """
OWASP Top 10:2025 categories the scanner can test:
  A01: Broken Access Control (IDOR, privilege escalation, SSRF, JWT issues)
  A02: Security Misconfiguration (exposed configs, default creds, CORS)
  A03: Software Supply Chain Failures (vulnerable libs, typosquats, missing SRI)
  A04: Cryptographic Failures (weak TLS, mixed content, weak hashing)
  A05: Injection (SQLi, XSS, command, NoSQL, LDAP, SSTI, XXE)
  A06: Insecure Design (race conditions, workflow bypass, business logic)
  A07: Authentication Failures (weak passwords, brute force, session issues)
  A08: Software/Data Integrity Failures (insecure deserialization, unsigned JWT)
  A09: Security Logging & Alerting Failures (silent failures, user enumeration)
  A10: Mishandling of Exceptional Conditions (stack traces leak, malformed input crashes)
"""


def _summarize_recon_for_ai(recon_data: dict, endpoints: List[dict],
                             forms: List[dict], techs: List[dict]) -> str:
    """Condense recon output into a compact AI-friendly summary."""
    tech_parts = []
    for t in techs[:20]:
        name = t.get("name", "")
        ver  = t.get("version")
        tech_parts.append(f"{name} v{ver}" if ver else name)
    tech_str = ", ".join(tech_parts) or "Unknown"

    # Bucket endpoints by kind
    page_urls = [e["url"] for e in endpoints if e.get("kind") == "page"][:15]
    api_urls  = [e["url"] for e in endpoints if e.get("kind") == "api"][:25]

    # Form summary
    form_strs = []
    for f in forms[:15]:
        inputs_summary = ", ".join(f'{i["name"]}({i["type"]})' for i in f.get("inputs", [])[:6])
        form_strs.append(f"- {f.get('method','POST')} {f.get('action','?')} "
                         f"[{f.get('purpose','other')}] inputs: {inputs_summary}")

    summary = f"""TARGET APPLICATION RECONNAISSANCE SUMMARY
==========================================
URL:          {recon_data.get('target_url', '?')}
Auth method:  {recon_data.get('auth_method') or 'unknown'}
Tech stack:   {tech_str}

DISCOVERED PAGES ({len(page_urls)} shown):
{chr(10).join(f"  - {u}" for u in page_urls) or "  (none)"}

DISCOVERED API ENDPOINTS ({len(api_urls)} shown):
{chr(10).join(f"  - {u}" for u in api_urls) or "  (none)"}

DISCOVERED FORMS ({len(form_strs)} shown):
{chr(10).join(form_strs) or "  (none)"}
"""
    return summary


def _build_ai_prompt(recon_summary: str) -> str:
    """Build the Groq prompt for attack planning."""
    return f"""You are a senior offensive security engineer planning a penetration test.

{recon_summary}

{OWASP_2025_REF}

Based on the reconnaissance data above, produce a JSON attack plan. Identify:

1. The TYPE of application (e.g. e-commerce, SaaS dashboard, blog, banking app, etc.)
2. The business logic flows that exist (e.g. login, signup, checkout, file upload, search, comment, password reset)
3. For each OWASP Top 10:2025 category, decide if it APPLIES to this app. If yes, list specific endpoints/forms to attack.
4. Identify business logic vulnerabilities that may exist (race conditions, IDOR, workflow bypass) given the discovered endpoints.

Respond ONLY with valid JSON in this exact schema (no markdown, no commentary):
{{
  "app_type": "string — e.g. 'e-commerce', 'saas_dashboard', 'corporate_marketing'",
  "business_flows": ["login", "checkout", "file_upload", ...],
  "owasp_priorities": {{
    "A01": {{ "applicable": true, "priority": "high|medium|low", "reasoning": "...", "target_endpoints": ["..."], "target_forms": ["..."] }},
    "A02": {{ "applicable": true, "priority": "high|medium|low", "reasoning": "...", "target_endpoints": ["..."], "target_forms": ["..."] }},
    "A03": {{ ... }},
    "A04": {{ ... }},
    "A05": {{ "applicable": true, "priority": "high", "reasoning": "Forms with text inputs are SQLi/XSS targets", "target_endpoints": ["..."], "target_forms": ["..."] }},
    "A06": {{ ... }},
    "A07": {{ ... }},
    "A08": {{ ... }},
    "A09": {{ ... }},
    "A10": {{ ... }}
  }},
  "business_logic_tests": [
    {{ "name": "test_race_condition_on_checkout", "endpoint": "/api/checkout", "description": "Try parallel checkouts to test race condition", "owasp": "A06" }},
    ...
  ],
  "high_value_targets": [
    {{ "url": "/api/users/:id", "reason": "User data endpoint — test IDOR", "owasp": "A01" }},
    ...
  ]
}}

Be conservative — only mark a category as 'applicable' if there's clear evidence in the recon data.
For 'priority': 'high' if forms/endpoints clearly exist for this attack, 'medium' if some indirect evidence, 'low' if speculative.
"""


def _call_groq_for_plan(prompt: str) -> Optional[dict]:
    """Call Groq with the planning prompt. Returns parsed JSON or None."""
    try:
        from groq import Groq
    except ImportError:
        logger.error("[AI Planner] groq package not available")
        return None

    api_keys = []
    for key_var in ("GROQ_API_KEY", "GROQ_API_KEY_2", "GROQ_API_KEY_3", "GROQ_API_KEY_4"):
        k = os.getenv(key_var, "").strip()
        if k and not k.startswith("PASTE_"):
            api_keys.append(k)

    if not api_keys:
        logger.error("[AI Planner] No Groq API keys configured")
        return None

    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

    # Try each key until one works (handles per-key rate limits)
    last_err = None
    for key in api_keys:
        try:
            client = Groq(api_key=key)
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a senior offensive security engineer. Respond ONLY with valid JSON, no other text."},
                    {"role": "user",   "content": prompt},
                ],
                max_tokens=2500,
                temperature=0.3,   # low temp for consistent, deterministic plans
                response_format={"type": "json_object"},
            )
            text = (resp.choices[0].message.content or "").strip()
            # Strip markdown fences if AI ignored instructions
            if text.startswith("```"):
                text = text.split("```", 2)[1]
                if text.lower().startswith("json"):
                    text = text[4:].strip()
                text = text.split("```", 1)[0]
            try:
                return json.loads(text)
            except json.JSONDecodeError as je:
                logger.warning(f"[AI Planner] JSON parse failed: {je}. Text: {text[:200]}")
                last_err = je
                continue
        except Exception as e:
            err_str = str(e)
            if "rate_limit" in err_str.lower() or "429" in err_str:
                logger.info(f"[AI Planner] Key rate-limited, trying next")
                last_err = e
                continue
            logger.error(f"[AI Planner] Groq call failed: {e}")
            last_err = e
            continue

    logger.error(f"[AI Planner] All keys exhausted: {last_err}")
    return None


def _fallback_plan(target_url: str, endpoints: List[dict], forms: List[dict]) -> dict:
    """
    Default attack plan when AI is unavailable.
    Conservatively enables all categories so attack engines still run.
    """
    # Heuristic: any forms with text inputs → injection target
    form_targets = [f["action"] for f in forms if any(
        i["type"] in ("text", "email", "search", "url", "textarea")
        for i in f.get("inputs", [])
    )]
    api_targets = [e["url"] for e in endpoints if e.get("kind") == "api"][:20]

    return {
        "app_type": "unknown",
        "business_flows": list({f.get("purpose", "other") for f in forms if f.get("purpose")}),
        "owasp_priorities": {
            f"A0{i}": {
                "applicable": True,
                "priority":   "medium",
                "reasoning":  "Fallback plan (AI unavailable) — running all categories at medium priority",
                "target_endpoints": api_targets[:10],
                "target_forms":     form_targets[:10],
            }
            for i in range(1, 10)
        } | {
            "A10": {
                "applicable": True,
                "priority":   "low",
                "reasoning":  "Fallback plan — exception handling tests will run with default payloads",
                "target_endpoints": api_targets[:5],
                "target_forms":     [],
            }
        },
        "business_logic_tests": [],
        "high_value_targets":   [{"url": u, "reason": "API endpoint discovered", "owasp": "A01"} for u in api_targets[:5]],
        "_fallback": True,
    }


# ─── Public entry point ──────────────────────────────────────────────────────

def generate_attack_plan(
    target_url: str,
    auth_method: Optional[str],
    endpoints: List[dict],
    forms: List[dict],
    techs: List[dict],
) -> dict:
    """
    Generate a structured attack plan for the target.

    Args:
        target_url:  the target URL string
        auth_method: detected auth (jwt | session_cookie | basic | oauth | None)
        endpoints:   list of endpoint dicts from DiscoveredEndpoint
        forms:       list of form dicts from DiscoveredForm
        techs:       list of tech dicts from DetectedTech

    Returns:
        dict with structure described in _build_ai_prompt schema
    """
    recon_data = {"target_url": target_url, "auth_method": auth_method}
    summary    = _summarize_recon_for_ai(recon_data, endpoints, forms, techs)
    prompt     = _build_ai_prompt(summary)

    plan = _call_groq_for_plan(prompt)
    if plan is None:
        logger.warning(f"[AI Planner] Using fallback plan for {target_url}")
        plan = _fallback_plan(target_url, endpoints, forms)

    # Add metadata
    plan["_meta"] = {
        "target_url":    target_url,
        "generated_at":  datetime.utcnow().isoformat() + "Z",
        "endpoint_count": len(endpoints),
        "form_count":    len(forms),
        "tech_count":    len(techs),
        "auth_method":   auth_method,
    }
    return plan
