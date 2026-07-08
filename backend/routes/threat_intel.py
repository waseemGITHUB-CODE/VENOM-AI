"""
VENOM AI · Threat Intelligence routes
  POST /api/threat/vt/check        — VirusTotal check (URL/IP/domain/hash)
  GET  /api/threat/cve/{cve_id}    — NVD CVE lookup
  GET  /api/threat/cve/search      — NVD CVE search by keyword
  GET  /api/threat/cve/recent      — Recent CVEs
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

router = APIRouter()


class VTRequest(BaseModel):
    target: str


@router.post("/vt/check")
async def virustotal_check(req: VTRequest):
    try:
        from services.virustotal_service import check_auto
        return check_auto(req.target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"VirusTotal error: {e}")


@router.get("/cve/{cve_id}")
async def cve_lookup(cve_id: str):
    try:
        from services.nvd_service import lookup_cve
        return lookup_cve(cve_id)
    except Exception as e:
        raise HTTPException(500, f"NVD error: {e}")


@router.get("/cve/search")
async def cve_search(
    q: str = Query(..., description="Keyword to search (product, vendor, vuln type)"),
    limit: int = Query(10, ge=1, le=20),
):
    try:
        from services.nvd_service import search_cves
        return {"results": search_cves(q, limit)}
    except Exception as e:
        raise HTTPException(500, f"NVD error: {e}")


@router.get("/cve/recent")
async def cve_recent(
    limit: int = Query(10, ge=1, le=20),
    severity: str = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
):
    try:
        from services.nvd_service import recent_cves
        return {"results": recent_cves(limit, severity)}
    except Exception as e:
        raise HTTPException(500, f"NVD error: {e}")
