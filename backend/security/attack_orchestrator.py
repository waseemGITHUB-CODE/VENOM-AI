"""
VENOM AI — Attack Orchestrator (Phase 2c integration)
─────────────────────────────────────────────────────────────────────────
Coordinates the full attack pipeline:

  Step 1 — RECON      → Phase 2a recon_engine.run_recon()
  Step 2 — PLAN       → Phase 2b ai_test_planner.generate_attack_plan()
  Step 3 — ATTACK     → Phase 2c attack_engines.a05_injection.run_a05_engine()
                       (more engines wired in 2d-2g)
  Step 4 — VERIFY     → de-dup, mark verified, kill false positives
  Step 5 — SCORE      → apply risk matrix (Phase 2h will refine)

Each step updates the AttackScan row so the frontend can poll progress.

SAFETY:
  - Hard timeout at 30 minutes (Celery-killed if Celery, threading.Event if local)
  - Cancellable mid-flight by status='cancelled'
  - Per-target rate limit enforced by AttackClient
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Optional, List

from sqlalchemy.orm import Session

from db.database import SessionLocal
from db.models import (
    AttackScan, AttackFinding, ReconResult,
    DiscoveredEndpoint, DiscoveredForm, DetectedTech,
)
from security.recon_engine import run_recon
from security.ai_test_planner import generate_attack_plan
from security.attack_engines.a01_access_control import run_a01_engine
from security.attack_engines.a02_misconfiguration import run_a02_engine
from security.attack_engines.a03_supply_chain import run_a03_engine
from security.attack_engines.a04_crypto_failures import run_a04_engine
from security.attack_engines.a05_injection import run_a05_engine
from security.attack_engines.a06_insecure_design import run_a06_engine
from security.attack_engines.a07_auth_failures import run_a07_engine
from security.attack_engines.a08_integrity_failures import run_a08_engine
from security.attack_engines.a09_logging_failures import run_a09_engine
from security.attack_engines.a10_exception_handling import run_a10_engine
from security.attack_engines.common import Finding
from security.audit import log_scan_event
from security.ai_enrichment import enrich_findings

logger = logging.getLogger("venom.orchestrator")


def _is_target_reachable(target_url: str, timeout: float = 8.0) -> bool:
    """
    Quick pre-flight check: can we actually connect to the target?
    Tries the given URL, then the other scheme, then a plain GET. Returns
    True if ANY attempt gets an HTTP response (any status code counts —
    even 403/500 means the host is alive). Fails fast on dead hosts so a
    scan doesn't grind through hundreds of request timeouts.
    """
    import httpx
    from urllib.parse import urlparse
    candidates = [target_url]
    try:
        p = urlparse(target_url)
        if p.scheme == "https":
            candidates.append(target_url.replace("https://", "http://", 1))
        elif p.scheme == "http":
            candidates.append(target_url.replace("http://", "https://", 1))
    except Exception:
        pass
    for url in candidates:
        try:
            with httpx.Client(timeout=timeout, follow_redirects=True, verify=False,
                              headers={"User-Agent": "VENOM-AI-Scanner/2.0"}) as c:
                r = c.get(url)
            if r.status_code:   # any response = host is alive
                return True
        except Exception:
            continue
    return False


# ── Tunables ────────────────────────────────────────────────────────────────
MAX_SCAN_DURATION_SECONDS = 30 * 60          # 30 minutes hard limit
PROGRESS_PHASES = {
    "queued":          0,
    "running_recon":   10,
    "planning":        40,
    "running_attacks": 50,
    "verifying":       90,
    "completed":      100,
    "failed":         100,
    "cancelled":      100,
}


# ── Cancellation handles (in-process registry) ──────────────────────────────
_cancel_events: dict[int, threading.Event] = {}
_cancel_lock = threading.Lock()


def request_cancel(scan_id: int):
    """Public: request cancellation of an in-flight scan."""
    with _cancel_lock:
        evt = _cancel_events.get(scan_id)
        if evt:
            evt.set()


def _is_cancelled(scan_id: int) -> bool:
    with _cancel_lock:
        evt = _cancel_events.get(scan_id)
        return bool(evt and evt.is_set())


def _register_cancel(scan_id: int) -> threading.Event:
    with _cancel_lock:
        evt = threading.Event()
        _cancel_events[scan_id] = evt
        return evt


def _unregister_cancel(scan_id: int):
    with _cancel_lock:
        _cancel_events.pop(scan_id, None)


# ── State update helpers ────────────────────────────────────────────────────

def _update_scan(db: Session, scan_id: int, **fields):
    """Atomic update of an AttackScan row."""
    try:
        scan = db.query(AttackScan).filter(AttackScan.id == scan_id).first()
        if scan:
            for k, v in fields.items():
                setattr(scan, k, v)
            # PROGRESS_PHASES only supplies a DEFAULT progress for a status when
            # the caller didn't pass an explicit one. Previously it always won,
            # which clobbered the fine-grained per-engine progress: every engine
            # start passes status="running_attacks" + a real 50→90 value, but the
            # override snapped it back to 50 each time, so the bar looked stuck at
            # 50% the whole run and then jumped straight to complete. Let an
            # explicit progress take precedence.
            if "progress" not in fields and "status" in fields and fields["status"] in PROGRESS_PHASES:
                scan.progress = PROGRESS_PHASES[fields["status"]]
            db.commit()
    except Exception as e:
        logger.error(f"[Orchestrator] _update_scan failed: {e}")
        try: db.rollback()
        except: pass


def _save_findings(db: Session, scan_id: int, findings: List) -> dict:
    """Persist Finding objects (or pre-enriched dicts) to DB. Returns count summary."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "hardening": 0}
    saved = 0
    for f in findings:
        try:
            # f may be a Finding dataclass or a dict (after AI enrichment converts)
            getf = (lambda k, d=None: getattr(f, k, d)) if not isinstance(f, dict) else f.get

            row = AttackFinding(
                scan_id        = scan_id,
                category       = getf("category"),
                owasp          = getf("owasp"),
                severity       = getf("severity"),
                title          = (getf("title") or "")[:500],
                description    = getf("description"),
                impact         = getf("impact"),
                recommendation = getf("recommendation"),
                affected_url   = (getf("affected_url") or "")[:1500],
                parameter      = (getf("parameter") or "")[:200],
                http_method    = (getf("http_method") or "GET")[:10],
                payload        = getf("payload"),
                evidence       = getf("evidence"),
                poc            = getf("poc"),
                cwe_id         = (getf("cwe_id") or "")[:20],
                cvss_score     = float(getf("cvss_score") or 0),
                likelihood     = int(getf("likelihood") or 3),
                impact_score   = int(getf("impact_score") or 3),
                risk_score     = int(getf("risk_score") or 9),
                verified       = bool(getf("verified")),
                confidence     = (getf("confidence") or "probable")[:20],
                confidence_reason = getf("confidence_reason"),
                source_tool    = (getf("source_tool") or "venom_active")[:50],
                request_sample = getf("request_sample"),
                response_sample= getf("response_sample"),
                # AI enrichment fields
                ai_explanation = getf("ai_explanation"),
                ai_code_fix    = getf("ai_code_fix"),
                ai_fix_language= (getf("ai_fix_language") or "")[:40] or None,
                ai_enriched_at = getf("ai_enriched_at"),
            )
            db.add(row)
            saved += 1
            # Update counts
            cat = getf("category")
            sev = (getf("severity") or "info").lower()
            if cat == "hardening":
                counts["hardening"] += 1
            elif sev in counts:
                counts[sev] += 1
        except Exception as e:
            logger.warning(f"[Orchestrator] Finding save error: {e}")
    try:
        db.commit()
    except Exception as e:
        logger.error(f"[Orchestrator] commit findings failed: {e}")
        db.rollback()
    return counts


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """
    Collapse duplicate findings of the SAME vulnerability type + title into ONE
    representative finding, regardless of how many URLs/params it appeared on.
    (Previously keyed on URL too, so the same SSTI across 32 forms produced 32
    rows — that noise is what made results look uniform.) We keep the first (most
    concrete) occurrence and note how many locations it was detected on.
    """
    groups: dict = {}
    order: list = []
    for f in findings:
        key = (f.owasp, (f.title or "").strip().lower())
        if key not in groups:
            groups[key] = [f]
            order.append(key)
        else:
            groups[key].append(f)

    out: List[Finding] = []
    for key in order:
        grp = groups[key]
        rep = grp[0]
        if len(grp) > 1:
            # Aggregate the distinct affected locations into the representative
            locs = []
            for g in grp:
                u = getattr(g, "affected_url", None)
                if u and u not in locs:
                    locs.append(u)
            try:
                note = f"\n\nDetected on {len(grp)} location(s)"
                if locs[:5]:
                    note += ": " + ", ".join(locs[:5]) + ("…" if len(locs) > 5 else "")
                rep.description = (rep.description or "") + note + "."
            except Exception:
                pass
        out.append(rep)
    return out


def _finding_to_dict(f: Finding) -> dict:
    """Convert a Finding dataclass to dict so AI enrichment can mutate it in place."""
    return {
        "title": f.title, "category": f.category, "owasp": f.owasp, "severity": f.severity,
        "cwe_id": f.cwe_id, "cvss_score": f.cvss_score,
        "affected_url": f.affected_url, "parameter": f.parameter, "http_method": f.http_method,
        "payload": f.payload, "evidence": f.evidence,
        "description": f.description, "impact": f.impact, "recommendation": f.recommendation,
        "poc": f.poc, "source_tool": f.source_tool, "verified": f.verified,
        "likelihood": f.likelihood, "impact_score": f.impact_score, "risk_score": f.risk_score,
        "request_sample": f.request_sample, "response_sample": f.response_sample,
        # Confidence fields — filled by verification.classify_and_rank()
        "confidence": "probable", "confidence_reason": None,
        # Enrichment fields start blank; ai_enrichment.py fills them
        "ai_explanation": None, "ai_code_fix": None, "ai_fix_language": None,
        "ai_enriched_at": None,
    }


# ── Main pipeline ───────────────────────────────────────────────────────────

def run_attack_scan(scan_id: int):
    """
    Run the full attack pipeline for an AttackScan row.
    This function ALWAYS creates its own DB session — safe to call from any thread.
    Wraps everything in try/finally so the scan row always ends in a terminal state.
    """
    cancel_event = _register_cancel(scan_id)
    db = SessionLocal()
    start_time = time.monotonic()

    try:
        scan = db.query(AttackScan).filter(AttackScan.id == scan_id).first()
        if not scan:
            logger.error(f"[Orchestrator] scan {scan_id} not found")
            return

        target_url = scan.target_url
        owner_id   = scan.owner_id
        enabled    = scan.enabled_categories or ["A05"]   # default: only what's built

        logger.info(f"[Orchestrator] Scan {scan_id} starting — target={target_url} "
                    f"categories={enabled}")

        # ─── Audit: scan started ──────────────────────────────────────────
        log_scan_event(db,
            action="attack_scan_started",
            target_url=target_url,
            owner_id=owner_id,
            domain_verified=scan.domain_verified,
            consent_given=scan.consent_given,
            scan_type="active",
            user_ip=scan.user_ip,
            allowed=True,
            metadata={"categories": enabled, "intensity": scan.scan_intensity},
        )

        # ──────────────────────────────────────────────────────────────────
        # STEP 0 — PRE-FLIGHT REACHABILITY CHECK
        # ──────────────────────────────────────────────────────────────────
        # A dead/unreachable target makes every subsequent request wait the
        # full timeout, so a scan would grind for many minutes ("stuck at 50%").
        # Fail fast here instead.
        _update_scan(db, scan_id, status="running_recon", phase="Checking target reachability")
        if not _is_target_reachable(target_url):
            _update_scan(db, scan_id,
                         status="failed",
                         phase="Target unreachable",
                         error=(f"Could not connect to {target_url}. The host is offline, "
                                f"does not exist, or is blocking requests. Check the URL and "
                                f"make sure the site is reachable, then try again."),
                         completed_at=datetime.utcnow(),
                         duration_s=time.monotonic() - start_time)
            logger.info(f"[Orchestrator] Scan {scan_id} aborted — target unreachable: {target_url}")
            return

        # ──────────────────────────────────────────────────────────────────
        # STEP 1 — RECON
        # ──────────────────────────────────────────────────────────────────
        _update_scan(db, scan_id, status="running_recon", phase="Discovering endpoints and tech stack")

        if _is_cancelled(scan_id):
            _update_scan(db, scan_id, status="cancelled", phase="Cancelled before recon")
            return

        recon_result = run_recon(db, target_url, owner_id=owner_id)
        recon_id = recon_result.get("recon_id")
        if recon_result.get("status") == "failed" or not recon_id:
            _update_scan(db, scan_id,
                         status="failed",
                         phase="Recon failed",
                         error=recon_result.get("error", "Recon failed without details"),
                         completed_at=datetime.utcnow(),
                         duration_s=time.monotonic() - start_time)
            return

        _update_scan(db, scan_id, recon_id=recon_id, progress=40,
                     phase=f"Recon done — {recon_result.get('total_urls', 0)} URLs, "
                           f"{recon_result.get('total_forms', 0)} forms")

        # Check timeout
        if time.monotonic() - start_time > MAX_SCAN_DURATION_SECONDS:
            _update_scan(db, scan_id, status="failed", phase="Timeout during recon",
                         error="Exceeded 30 min budget", completed_at=datetime.utcnow(),
                         duration_s=time.monotonic() - start_time)
            return

        # ──────────────────────────────────────────────────────────────────
        # STEP 2 — AI ATTACK PLAN
        # ──────────────────────────────────────────────────────────────────
        if _is_cancelled(scan_id):
            _update_scan(db, scan_id, status="cancelled", phase="Cancelled after recon")
            return

        _update_scan(db, scan_id, status="planning", phase="AI generating attack plan")

        # Load recon results from DB for the planner
        endpoints = db.query(DiscoveredEndpoint).filter(
            DiscoveredEndpoint.recon_id == recon_id).all()
        forms = db.query(DiscoveredForm).filter(
            DiscoveredForm.recon_id == recon_id).all()
        techs = db.query(DetectedTech).filter(
            DetectedTech.recon_id == recon_id).all()
        recon_row = db.query(ReconResult).filter(ReconResult.id == recon_id).first()

        endpoints_dict = [{
            "url": e.url, "kind": e.kind, "parameters": e.parameters or [],
            "status_code": e.status_code, "content_type": e.content_type,
        } for e in endpoints]
        forms_dict = [{
            "action": f.action, "method": f.method, "enctype": f.enctype,
            "inputs": f.inputs or [], "purpose": f.purpose,
            "has_csrf_token": f.has_csrf_token,
        } for f in forms]
        techs_dict = [{
            "name": t.name, "version": t.version, "category": t.category,
            "confidence": t.confidence,
        } for t in techs]

        plan = generate_attack_plan(
            target_url=target_url,
            auth_method=recon_row.auth_method if recon_row else None,
            endpoints=endpoints_dict,
            forms=forms_dict,
            techs=techs_dict,
        )
        _update_scan(db, scan_id, attack_plan=plan, progress=50,
                     phase=f"Plan generated — app type: {plan.get('app_type', 'unknown')}")

        # ──────────────────────────────────────────────────────────────────
        # STEP 3 — RUN ATTACK ENGINES
        # ──────────────────────────────────────────────────────────────────
        all_findings: List[Finding] = []
        max_rps = scan.max_rps or 10

        # Pre-progress per-engine: split the 50%-90% band evenly across enabled engines
        engine_slots = [c for c in ("A01", "A02", "A03", "A04", "A05",
                                     "A06", "A07", "A08", "A09", "A10") if c in enabled]
        slot_count = max(len(engine_slots), 1)
        slot_step  = max(1, 40 // slot_count)

        def _start_engine(code: str, label: str, slot_idx: int):
            if _is_cancelled(scan_id):
                _update_scan(db, scan_id, status="cancelled",
                             phase=f"Cancelled before {code}",
                             current_engine=None)
                return False
            _update_scan(db, scan_id,
                         status="running_attacks",
                         current_engine=code,
                         phase=label,
                         progress=50 + slot_idx * slot_step)
            return True

        def _finish_engine(code: str, slot_idx: int, found: int):
            _update_scan(db, scan_id,
                         phase=f"{code} done — {found} finding(s)",
                         progress=50 + (slot_idx + 1) * slot_step)

        # A01
        if "A01" in enabled:
            slot = engine_slots.index("A01")
            if not _start_engine("A01", "A01 Access Control — IDOR, SSRF, JWT, forced browsing", slot):
                return
            try:
                r = run_a01_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A01 produced {len(r)} findings")
                _finish_engine("A01", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A01 engine error: {e}", exc_info=True)

        # A02
        if "A02" in enabled:
            slot = engine_slots.index("A02")
            if not _start_engine("A02", "A02 Misconfig — exposed files, debug pages, CORS, defaults", slot):
                return
            try:
                r = run_a02_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A02 produced {len(r)} findings")
                _finish_engine("A02", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A02 engine error: {e}", exc_info=True)

        # A03 — Software Supply Chain (vulnerable libs, exposed manifests, SRI, EOL)
        if "A03" in enabled:
            slot = engine_slots.index("A03")
            if not _start_engine("A03", "A03 Supply Chain — vulnerable libs, exposed manifests, SRI, EOL software", slot):
                return
            try:
                r = run_a03_engine(plan, endpoints_dict, forms_dict, target_url,
                                   detected_tech=techs_dict, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A03 produced {len(r)} findings")
                _finish_engine("A03", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A03 engine error: {e}", exc_info=True)

        # A04
        if "A04" in enabled:
            slot = engine_slots.index("A04")
            if not _start_engine("A04", "A04 Crypto Failures — TLS, HTTPS, cookies, sensitive data", slot):
                return
            try:
                r = run_a04_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A04 produced {len(r)} findings")
                _finish_engine("A04", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A04 engine error: {e}", exc_info=True)

        # A05
        if "A05" in enabled:
            slot = engine_slots.index("A05")
            if not _start_engine("A05", "A05 Injection — SQLi, XSS, Command, NoSQL, SSTI, XXE", slot):
                return
            try:
                r = run_a05_engine(plan, endpoints_dict, forms_dict, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A05 produced {len(r)} findings")
                _finish_engine("A05", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A05 engine error: {e}", exc_info=True)

        # A06 — Insecure Design (CSRF, no rate-limit, business logic)
        if "A06" in enabled:
            slot = engine_slots.index("A06")
            if not _start_engine("A06", "A06 Insecure Design — CSRF, rate-limiting, business logic", slot):
                return
            try:
                r = run_a06_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A06 produced {len(r)} findings")
                _finish_engine("A06", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A06 engine error: {e}", exc_info=True)

        # A07 — Authentication Failures (enumeration, session-in-URL, transport)
        if "A07" in enabled:
            slot = engine_slots.index("A07")
            if not _start_engine("A07", "A07 Auth Failures — enumeration, session tokens, transport", slot):
                return
            try:
                r = run_a07_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A07 produced {len(r)} findings")
                _finish_engine("A07", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A07 engine error: {e}", exc_info=True)

        # A08 — Software/Data Integrity (deserialization, source maps, CI/CD)
        if "A08" in enabled:
            slot = engine_slots.index("A08")
            if not _start_engine("A08", "A08 Integrity — deserialization, source maps, CI/CD exposure", slot):
                return
            try:
                r = run_a08_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A08 produced {len(r)} findings")
                _finish_engine("A08", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A08 engine error: {e}", exc_info=True)

        # A09 — Security Logging & Alerting Failures (no attack detection)
        if "A09" in enabled:
            slot = engine_slots.index("A09")
            if not _start_engine("A09", "A09 Logging & Alerting — attack-detection probing", slot):
                return
            try:
                r = run_a09_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A09 produced {len(r)} findings")
                _finish_engine("A09", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A09 engine error: {e}", exc_info=True)

        # A10 — Mishandling of Exceptional Conditions (malformed input, errors)
        if "A10" in enabled:
            slot = engine_slots.index("A10")
            if not _start_engine("A10", "A10 Exception Mishandling — malformed input, error handling", slot):
                return
            try:
                r = run_a10_engine(plan, endpoints_dict, forms_dict, target_url, max_rps=max_rps)
                all_findings.extend(r)
                logger.info(f"[Orchestrator] A10 produced {len(r)} findings")
                _finish_engine("A10", slot, len(r))
            except Exception as e:
                logger.error(f"[Orchestrator] A10 engine error: {e}", exc_info=True)

        # ──────────────────────────────────────────────────────────────────
        # STEP 4 — VERIFY + DEDUPE
        # ──────────────────────────────────────────────────────────────────
        _update_scan(db, scan_id, status="verifying", phase="Verifying findings, removing duplicates")
        deduped = _dedupe_findings(all_findings)

        # ──────────────────────────────────────────────────────────────────
        # STEP 4.5 — AI ENRICHMENT — explanation + code fix for each finding
        # ──────────────────────────────────────────────────────────────────
        _update_scan(db, scan_id, status="verifying",
                     current_engine="enrichment",
                     phase=f"AI enriching {len(deduped)} findings with explanations + code fixes",
                     progress=94)
        # Convert to dicts so enrichment can mutate
        enriched_dicts = [_finding_to_dict(f) for f in deduped]

        # ── Confidence classification + prioritisation (true positives first) ─
        # Tags each finding confirmed | probable | suspected | hardening and
        # sorts so proven/exploitable findings come first.
        try:
            from security.verification import classify_and_rank
            classify_and_rank(enriched_dicts)
        except Exception as e:
            logger.error(f"[Orchestrator] Verification pass failed (non-fatal): {e}", exc_info=True)

        try:
            tech_summary = recon_row.stack_summary if recon_row else {}
            enrich_findings(enriched_dicts, target_url=target_url, tech_summary=tech_summary)
        except Exception as e:
            logger.error(f"[Orchestrator] AI enrichment failed (non-fatal): {e}", exc_info=True)

        # ──────────────────────────────────────────────────────────────────
        # STEP 5 — SAVE (now with confidence + enrichment fields populated)
        # ──────────────────────────────────────────────────────────────────
        counts = _save_findings(db, scan_id, enriched_dicts)

        duration = time.monotonic() - start_time
        _update_scan(db, scan_id,
                     status="completed",
                     phase=f"Done — {len(deduped)} findings in {duration:.1f}s",
                     progress=100,
                     total_findings=sum(v for k, v in counts.items() if k != "hardening"),
                     critical_count=counts.get("critical", 0),
                     high_count=counts.get("high", 0),
                     medium_count=counts.get("medium", 0),
                     low_count=counts.get("low", 0),
                     hardening_count=counts.get("hardening", 0),
                     completed_at=datetime.utcnow(),
                     duration_s=duration)

        # Final audit log
        log_scan_event(db,
            action="attack_scan_completed",
            target_url=target_url,
            owner_id=owner_id,
            domain_verified=scan.domain_verified,
            consent_given=scan.consent_given,
            scan_type="active",
            user_ip=scan.user_ip,
            allowed=True,
            metadata={
                "duration_s": duration,
                "total_findings": len(deduped),
                "counts": counts,
            },
        )
        logger.info(f"[Orchestrator] Scan {scan_id} COMPLETE — {len(deduped)} findings, "
                    f"{counts.get('critical',0)} critical, {duration:.1f}s")

    except Exception as e:
        logger.error(f"[Orchestrator] Scan {scan_id} CRASHED: {e}", exc_info=True)
        try:
            _update_scan(db, scan_id,
                         status="failed",
                         phase="Crashed",
                         error=str(e)[:500],
                         completed_at=datetime.utcnow(),
                         duration_s=time.monotonic() - start_time)
        except Exception:
            pass
    finally:
        _unregister_cancel(scan_id)
        try:
            db.close()
        except Exception:
            pass
