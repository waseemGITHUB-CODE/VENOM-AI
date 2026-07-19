"""
VENOM AI — Domain Verification Routes (Phase 2a)
─────────────────────────────────────────────────────────────────────────
Endpoints:
  POST   /api/verify/domain/add           — register a new domain to verify
  GET    /api/verify/domain/instructions/{id}  — get 4-method instructions
  POST   /api/verify/domain/check/{id}    — run verification check NOW
  GET    /api/verify/domain/list          — list user's domains
  DELETE /api/verify/domain/{id}          — remove a domain
  GET    /api/verify/reachable            — is this target even up? (pre-flight
                                             check used by Scanner/Threat Intel/
                                             NHI Scanner before running anything)
"""
from __future__ import annotations

import logging
import socket
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db.database import get_db
from db.models import User as _AuthUser, VerifiedDomain
from auth.dependencies import get_optional_user
from auth.rate_limit import rate_limit

from security.domain_verify import (
    normalize_domain, generate_token, check_domain_ownership,
    get_verification_instructions,
)
from security.audit import log_scan_event

logger = logging.getLogger("venom.verify")
router = APIRouter()


# ─── Schemas ─────────────────────────────────────────────────────────────────

class AddDomainRequest(BaseModel):
    domain: str


def _require_user(user: Optional[_AuthUser]) -> _AuthUser:
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def _domain_to_dict(d: VerifiedDomain) -> dict:
    return {
        "id":                d.id,
        "domain":            d.domain,
        "verified":          d.verified,
        "verified_via":      d.verified_via,
        "verified_at":       d.verified_at.isoformat() if d.verified_at else None,
        "last_check_at":     d.last_check_at.isoformat() if d.last_check_at else None,
        "last_check_error":  d.last_check_error,
        "revoked_at":        d.revoked_at.isoformat() if d.revoked_at else None,
        "created_at":        d.created_at.isoformat() if d.created_at else None,
        "verification_token": d.verification_token if not d.verified else None,
    }


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.post("/domain/add")
def add_domain(
    req: AddDomainRequest,
    request: Request,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=10, period_seconds=60)),
):
    """Register a new domain for ownership verification."""
    user = _require_user(current_user)
    domain = normalize_domain(req.domain)
    if not domain:
        raise HTTPException(status_code=400, detail="Invalid domain format. Use 'example.com' (no scheme, no path).")

    # Already exists for this user?
    existing = db.query(VerifiedDomain).filter(
        VerifiedDomain.owner_id == user.id,
        VerifiedDomain.domain == domain,
    ).first()
    if existing:
        return {"message": "Domain already registered", "domain": _domain_to_dict(existing)}

    token = generate_token()
    new_domain = VerifiedDomain(
        owner_id=user.id,
        domain=domain,
        verification_token=token,
        verified=False,
    )
    db.add(new_domain)
    db.commit()
    db.refresh(new_domain)

    log_scan_event(
        db,
        action="domain_added",
        target_url=domain,
        owner_id=user.id,
        user_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        allowed=True,
    )

    return {
        "message": f"Domain {domain} registered. Complete verification to enable active scans.",
        "domain":  _domain_to_dict(new_domain),
    }


@router.get("/domain/instructions/{domain_id}")
def domain_instructions(
    domain_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Return verification instructions for all 4 methods."""
    user = _require_user(current_user)
    d = db.query(VerifiedDomain).filter(
        VerifiedDomain.id == domain_id,
        VerifiedDomain.owner_id == user.id,
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    return get_verification_instructions(d.domain, d.verification_token)


@router.post("/domain/check/{domain_id}")
def check_domain(
    domain_id: int,
    request: Request,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
    _rl: None = Depends(rate_limit(max_calls=10, period_seconds=60)),
):
    """Trigger a verification check against the domain."""
    user = _require_user(current_user)
    d = db.query(VerifiedDomain).filter(
        VerifiedDomain.id == domain_id,
        VerifiedDomain.owner_id == user.id,
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")

    verified, method, evidence = check_domain_ownership(d.domain, d.verification_token)

    d.last_check_at = datetime.utcnow()
    if verified:
        d.verified         = True
        d.verified_via     = method
        d.verified_at      = datetime.utcnow()
        d.revoked_at       = None
        d.last_check_error = None
    else:
        d.last_check_error = (evidence or "Verification failed")[:1000]
    db.commit()

    log_scan_event(
        db,
        action="domain_verified" if verified else "domain_verify_failed",
        target_url=d.domain,
        owner_id=user.id,
        domain_verified=verified,
        user_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        allowed=True,
        metadata={"method": method, "evidence": evidence},
    )

    return {
        "verified":     verified,
        "method":       method,
        "evidence":     evidence,
        "domain":       _domain_to_dict(d),
    }


@router.get("/domain/list")
def list_domains(
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all of the current user's registered domains."""
    user = _require_user(current_user)
    rows = db.query(VerifiedDomain).filter(
        VerifiedDomain.owner_id == user.id,
    ).order_by(VerifiedDomain.created_at.desc()).all()
    return {
        "domains":          [_domain_to_dict(d) for d in rows],
        "total":            len(rows),
        "verified_count":   sum(1 for d in rows if d.verified and d.revoked_at is None),
    }


@router.delete("/domain/{domain_id}")
def delete_domain(
    domain_id: int,
    current_user: Optional[_AuthUser] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Remove a domain from the user's list."""
    user = _require_user(current_user)
    d = db.query(VerifiedDomain).filter(
        VerifiedDomain.id == domain_id,
        VerifiedDomain.owner_id == user.id,
    ).first()
    if not d:
        raise HTTPException(status_code=404, detail="Domain not found")
    db.delete(d)
    db.commit()
    return {"message": "Domain removed"}


# ─────────────────────────────────────────────────────────────────────────
#  Reachability pre-flight — "does this target even exist" check, run BEFORE
#  the Scanner / Threat Intel / NHI Scanner do anything real, so a typo'd or
#  dead domain fails fast with a clear message instead of burning a full
#  scan cycle (or, for Threat Intel, returning a confusing VirusTotal /
#  NVD error) on something that was never going to work.
# ─────────────────────────────────────────────────────────────────────────
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


@router.get("/reachable")
def check_reachable(url: str = Query(..., description="URL, bare domain, or IP to check")):
    raw = url.strip()
    if not raw:
        raise HTTPException(400, "No target provided")

    full = raw if "://" in raw else f"https://{raw}"
    try:
        host = urlparse(full).hostname or ""
    except Exception:
        host = ""
    if not host:
        return {"reachable": False, "dns_resolved": False, "http_ok": None,
                "resolved_ip": None, "message": "Not a valid URL or domain."}

    if host in _LOCAL_HOSTS or host.startswith("192.168.") or host.startswith("10.") or host.endswith(".local"):
        return {"reachable": True, "dns_resolved": True, "http_ok": None,
                "resolved_ip": host, "message": "Local target — skipping reachability check."}

    # 1) DNS — does this hostname resolve at all? This alone answers "does
    #    this domain exist" for the vast majority of typo/fake-domain cases.
    resolved_ip = None
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(5.0)
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"reachable": False, "dns_resolved": False, "http_ok": None,
                "resolved_ip": None,
                "message": f'"{host}" does not exist — DNS lookup failed. Check for a typo.'}
    except Exception as e:
        return {"reachable": False, "dns_resolved": False, "http_ok": None,
                "resolved_ip": None, "message": f"Could not resolve \"{host}\": {e}"}
    finally:
        socket.setdefaulttimeout(old_timeout)

    # 2) HTTP — is something actually listening? A failure here is a softer
    #    signal than a DNS failure (the domain is real but may be down, or
    #    just slow/blocking automated probes), so it downgrades reachable
    #    to a warning rather than a hard block.
    http_ok = False
    try:
        import httpx
        with httpx.Client(timeout=6.0, follow_redirects=True, verify=False,
                           headers={"User-Agent": "VENOM-AI-Reachability/1.0"}) as client:
            try:
                r = client.head(full)
            except httpx.HTTPError:
                r = client.get(full)
            http_ok = r.status_code < 500
    except Exception:
        http_ok = False

    if http_ok:
        return {"reachable": True, "dns_resolved": True, "http_ok": True,
                "resolved_ip": resolved_ip, "message": f'"{host}" is up (resolved to {resolved_ip}).'}
    return {"reachable": True, "dns_resolved": True, "http_ok": False,
            "resolved_ip": resolved_ip,
            "message": f'"{host}" resolves ({resolved_ip}) but did not respond to an HTTP request — it may be down, slow, or blocking automated requests. You can still proceed.'}
