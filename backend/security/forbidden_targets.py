"""
VENOM AI — Forbidden Targets
─────────────────────────────────────────────────────────────────────────
Targets VENOM will NEVER scan, regardless of who requests it.
This is a hard safety net to prevent legal liability.

Categories:
  • government — .gov, .mil, .gob (Spanish gov), and country-specific
  • military   — defense-related domains
  • financial  — major banks (could trigger fraud detection)
  • healthcare — hospitals (HIPAA-sensitive, lives at stake)
  • education  — university LMS, .edu (academic networks)
  • critical   — critical infrastructure (utilities, power, water)

The seed runs on every API startup — entries are upserted, never deleted.
Admins can add custom blocks via the admin panel later.
"""
from __future__ import annotations
import logging
import re
from typing import Optional
from sqlalchemy.orm import Session

logger = logging.getLogger("venom.forbidden")


# Hard-coded list — these are absolute blocks
FORBIDDEN_PATTERNS = [
    # ── Government (worldwide TLDs) ────────────────────────────────────
    {"pattern": "*.gov",        "category": "government", "reason": "US government domain"},
    {"pattern": "*.gov.in",     "category": "government", "reason": "Indian government domain"},
    {"pattern": "*.gov.uk",     "category": "government", "reason": "UK government domain"},
    {"pattern": "*.gov.au",     "category": "government", "reason": "Australian government domain"},
    {"pattern": "*.gov.ca",     "category": "government", "reason": "Canadian government domain"},
    {"pattern": "*.gc.ca",      "category": "government", "reason": "Canadian federal government"},
    {"pattern": "*.gob.*",      "category": "government", "reason": "Spanish-language government domain"},
    {"pattern": "*.gouv.fr",    "category": "government", "reason": "French government domain"},
    {"pattern": "*.go.jp",      "category": "government", "reason": "Japanese government"},
    {"pattern": "*.go.kr",      "category": "government", "reason": "South Korean government"},

    # ── Military ────────────────────────────────────────────────────────
    {"pattern": "*.mil",        "category": "military",   "reason": "US military domain"},
    {"pattern": "*.mod.uk",     "category": "military",   "reason": "UK Ministry of Defence"},
    {"pattern": "*.mil.in",     "category": "military",   "reason": "Indian military"},

    # ── Major Financial (top banks worldwide) ──────────────────────────
    {"pattern": "*.rbi.org.in", "category": "financial",  "reason": "Reserve Bank of India"},
    {"pattern": "*.sbi.co.in",  "category": "financial",  "reason": "State Bank of India"},
    {"pattern": "*.hdfcbank.com", "category": "financial", "reason": "HDFC Bank"},
    {"pattern": "*.icicibank.com", "category": "financial", "reason": "ICICI Bank"},
    {"pattern": "*.axisbank.com", "category": "financial", "reason": "Axis Bank"},
    {"pattern": "*.federalreserve.gov", "category": "financial", "reason": "US Federal Reserve"},
    {"pattern": "*.jpmorganchase.com", "category": "financial", "reason": "JPMorgan Chase"},
    {"pattern": "*.bankofamerica.com", "category": "financial", "reason": "Bank of America"},
    {"pattern": "*.wellsfargo.com",    "category": "financial", "reason": "Wells Fargo"},

    # ── Healthcare ─────────────────────────────────────────────────────
    {"pattern": "*.nih.gov",    "category": "healthcare", "reason": "US National Institutes of Health"},
    {"pattern": "*.who.int",    "category": "healthcare", "reason": "World Health Organization"},
    {"pattern": "*.aiims.edu",  "category": "healthcare", "reason": "AIIMS (India)"},

    # ── Education TLDs ─────────────────────────────────────────────────
    {"pattern": "*.edu",        "category": "education",  "reason": "Educational institution (US)"},
    {"pattern": "*.ac.in",      "category": "education",  "reason": "Academic institution (India)"},
    {"pattern": "*.ac.uk",      "category": "education",  "reason": "Academic institution (UK)"},
    {"pattern": "*.edu.au",     "category": "education",  "reason": "Academic institution (Australia)"},

    # ── Critical Infrastructure / Strategic ────────────────────────────
    {"pattern": "*.icann.org",  "category": "critical",   "reason": "ICANN (internet governance)"},
    {"pattern": "*.iana.org",   "category": "critical",   "reason": "IANA (internet numbers)"},
    {"pattern": "*.ietf.org",   "category": "critical",   "reason": "IETF (internet standards)"},

    # ── VENOM AI itself ─────────────────────────────────────────────────
    {"pattern": "*.venomai.*",  "category": "platform",   "reason": "VENOM AI's own infrastructure"},
]


def seed_forbidden_targets(db: Session) -> int:
    """
    Seed forbidden targets table. Idempotent — safe to run on every startup.
    Returns number of new entries inserted.
    """
    try:
        from db.models import ForbiddenTarget
    except ImportError:
        return 0

    inserted = 0
    try:
        for entry in FORBIDDEN_PATTERNS:
            existing = db.query(ForbiddenTarget).filter(
                ForbiddenTarget.pattern == entry["pattern"]
            ).first()
            if existing:
                continue
            db.add(ForbiddenTarget(
                pattern=entry["pattern"],
                category=entry["category"],
                reason=entry["reason"],
                added_by="system_seed",
            ))
            inserted += 1
        if inserted:
            db.commit()
            logger.info(f"[ForbiddenTargets] Seeded {inserted} new entries")
        return inserted
    except Exception as e:
        logger.error(f"[ForbiddenTargets] Seed failed: {e}")
        try:
            db.rollback()
        except Exception:
            pass
        return 0


def _domain_matches_pattern(domain: str, pattern: str) -> bool:
    """
    Check if a domain matches a wildcard pattern.

    Pattern forms:
      "example.com"      → exact match
      "*.gov"            → suffix match: foo.gov, www.foo.gov → match
      "*.gob.*"          → contains: domain has ".gob." in it
      "::bank::"         → substring (between :: markers)
    """
    domain = domain.lower().strip()
    pattern = pattern.lower().strip()

    # Substring marker
    if pattern.startswith("::") and pattern.endswith("::"):
        return pattern[2:-2] in domain

    # Wildcard pattern
    if "*" in pattern:
        # Convert wildcard to regex
        regex_pattern = re.escape(pattern).replace(r"\*", ".*")
        return bool(re.match(f"^{regex_pattern}$", domain))

    # Exact match — but also match if pattern is a suffix preceded by a dot
    if domain == pattern:
        return True
    if domain.endswith("." + pattern):
        return True
    return False


def check_forbidden(db: Session, target_url: str) -> Optional[dict]:
    """
    Check if a target URL is on the forbidden list.
    Returns None if allowed, or a dict {pattern, category, reason} if forbidden.
    """
    try:
        from db.models import ForbiddenTarget
        from urllib.parse import urlparse
    except ImportError:
        return None

    try:
        parsed = urlparse(target_url if "://" in target_url else "https://" + target_url)
        domain = (parsed.hostname or "").lower()
        if not domain:
            return None

        # Walk every active pattern
        patterns = db.query(ForbiddenTarget).all()
        for p in patterns:
            if _domain_matches_pattern(domain, p.pattern):
                return {
                    "pattern":  p.pattern,
                    "category": p.category,
                    "reason":   p.reason,
                }
        return None
    except Exception as e:
        logger.error(f"[ForbiddenTargets] Check failed: {e}")
        return None
