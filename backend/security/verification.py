"""
VENOM AI — Finding Verification & Confidence Classifier
─────────────────────────────────────────────────────────────────────────
After the attack engines produce findings, this pass assigns each one a
CONFIDENCE tier so the UI can prioritise true positives and hide/deprioritise
false-positive-prone findings.

Tiers (highest → lowest):
  confirmed  — proven exploitable (error/reflection/timing/diff/metadata proof)
  probable   — strong behavioural/version signal, not a live exploit
  suspected  — only a clue exists ("path exists"); verify manually (FP-prone)
  hardening  — not directly exploitable; a best-practice/config improvement

The classifier is deterministic and rule-based (no AI needed) so it's fast
and predictable. Rules are keyed on (owasp, title keywords, verified flag).
"""
from __future__ import annotations

import logging
from typing import List

logger = logging.getLogger("venom.verification")

CONFIDENCE_RANK = {"confirmed": 0, "probable": 1, "suspected": 2, "hardening": 3}


# ── Title keyword sets ──────────────────────────────────────────────────────
# Findings whose title contains any of these are treated as PROVEN exploits
# because the engine confirmed them with a hard signal.
_CONFIRMED_KEYWORDS = [
    # A05 injection — all proven by error / reflection / timing / template-eval
    "sql injection", "reflected xss", "reflected cross-site", "command injection",
    "nosql injection", "template injection", "ssti", "xml external entity", "xxe",
    # A01 — proven by response diff / metadata / accepted forged token
    "idor", "cloud metadata", "alg=none",
    # A02 — proven by content / successful login
    "default credentials accepted",
]

# Confirmed ONLY when the exposed file's content was verified (high-signal files)
_CONFIRMED_EXPOSED_FILES = ["/.env", "/.git", "backup.sql", "dump.sql", "database.sql",
                            "/.htpasswd", "composer.lock", "package-lock", "source map"]

# Findings that are strong but not a live exploit → PROBABLE
_PROBABLE_KEYWORDS = [
    "no rate limiting", "username enumeration", "session/auth token in url",
    "login form submits over http", "cors origin reflection", "cors wildcard",
    "debug page exposed", "outdated", "end-of-life", "subresource integrity",
    "serialized object exposed", "exposed ci/cd", "exposed package manifest",
    "no attack detection", "verbose error", "unhandled exception",
    "ssl certificate expired", "self-signed", "hostname mismatch", "weak tls",
    "boolean-based blind", "time-based blind",
]

# Findings that are only a CLUE → SUSPECTED (verify manually, FP-prone)
_SUSPECTED_KEYWORDS = [
    "sensitive path exposed", "missing csrf", "csrf protection",
    "negative value accepted", "possible ssrf", "cors 'null'",
    "http trace", "server header reveals", "x-powered-by",
    "version disclosed", "version disclosure", "reveals version",
]

# Admin/login-ish paths — "exists" is NOT proof of unauthenticated access
_LOGIN_LIKE_PATHS = ["/admin", "/administrator", "/wp-admin", "/wp-login",
                     "/login", "/dashboard", "/cp", "/manage", "/management",
                     "/control-panel", "/console"]


def _classify(f: dict) -> tuple:
    """Return (confidence_tier, reason) for one finding dict."""
    category = (f.get("category") or "vulnerability").lower()
    title = (f.get("title") or "").lower()
    owasp = (f.get("owasp") or "").upper()
    verified = bool(f.get("verified"))
    evidence = (f.get("evidence") or "").lower()

    # 1. Hardening is never an exploitable vuln
    if category == "hardening":
        return "hardening", "Best-practice / configuration improvement, not directly exploitable."

    # 2. Exposed high-signal files with confirmed content = CONFIRMED
    if any(k in title for k in ("exposed file", "sensitive path", "sensitive file")):
        if any(hf in title or hf in evidence for hf in _CONFIRMED_EXPOSED_FILES):
            return "confirmed", "Sensitive file content was retrieved and confirmed."
        # An admin/login path merely returning 200 is only a clue
        if any(lp in title or lp in evidence for lp in _LOGIN_LIKE_PATHS):
            return "suspected", ("Path exists (HTTP 200) but this is typically a login page — "
                                 "confirm it grants access WITHOUT authentication.")
        # Other exposed paths — probable
        return "probable", "A sensitive path returned content; confirm it exposes real data."

    # 3. Proven exploit keywords
    if verified and any(k in title for k in _CONFIRMED_KEYWORDS):
        return "confirmed", "Engine proved this with a hard signal (error/reflection/timing/diff)."

    # 4. Suspected (clue-only) keywords take priority over probable for FP control
    if any(k in title for k in _SUSPECTED_KEYWORDS):
        return "suspected", ("Only a clue was observed; may be mitigated by controls VENOM "
                             "cannot see (SameSite, header tokens, WAF). Verify manually.")

    # 5. Probable keywords
    if any(k in title for k in _PROBABLE_KEYWORDS):
        return "probable", "Strong behavioural/version signal, but not exploited live."

    # 6. Fallbacks by verified flag
    if verified:
        return "probable", "Verified by the engine but without a definitive exploit proof."
    return "suspected", "Unverified indicator — manual confirmation recommended."


def classify_and_rank(findings: List[dict]) -> List[dict]:
    """
    Assign a `confidence` + `confidence_reason` to every finding, then sort so
    the most trustworthy/exploitable findings come first. Mutates + returns.

    Sort order:
      1. confidence tier (confirmed → probable → suspected → hardening)
      2. risk_score desc within a tier
    """
    for f in findings:
        tier, reason = _classify(f)
        f["confidence"] = tier
        f["confidence_reason"] = reason

    findings.sort(key=lambda f: (
        CONFIDENCE_RANK.get(f.get("confidence", "suspected"), 2),
        -int(f.get("risk_score", 0) or 0),
    ))

    counts = {}
    for f in findings:
        counts[f["confidence"]] = counts.get(f["confidence"], 0) + 1
    logger.info(f"[Verification] Confidence breakdown: {counts}")
    return findings
