from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Optional
from urllib.parse import urlparse
from datetime import datetime, timezone
import os

from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt
from app.core.phish_scanner import run_scan, SUPPORTED_MODELS

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# service-role client bypasses RLS — used only for server-side writes
_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase


class ScanRequest(BaseModel):
    url: str
    domain: Optional[str] = None   # if omitted, extracted from url automatically
    model: str = "claude-sonnet-4-6"


def _check_enterprise_access(user_id: str):
    """
    Raises 403 if the user lacks a valid active enterprise subscription
    or has zero/missing balance (balance is a column on user_subscriptions).
    """
    sub_res = (
        supabase
        .table("user_subscriptions")
        .select("plan_id, status, current_period_end, balance")
        .eq("user_id", user_id)
        .execute()
    )

    if not sub_res.data:
        raise HTTPException(status_code=403, detail="No subscription found")

    sub = sub_res.data[0]

    if sub.get("plan_id") != "enterprise":
        raise HTTPException(
            status_code=403,
            detail="Enterprise subscription required to access this feature",
        )

    if sub.get("status") != "active":
        raise HTTPException(
            status_code=403,
            detail=f"Subscription is not active (status: {sub.get('status')})",
        )

    period_end = sub.get("current_period_end")
    if period_end:
        end_dt = datetime.fromisoformat(period_end.replace("Z", "+00:00"))
        if end_dt < datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Subscription has expired")

    balance = sub.get("balance", 0)
    if not balance or float(balance) <= 0:
        raise HTTPException(
            status_code=403,
            detail="Insufficient wallet balance to perform a scan",
        )


def _upload_to_whois_phish(analysis: dict):
    import json as _json
    from urllib.parse import urlparse as _urlparse
    try:
        domain = (
            _urlparse(analysis.get("url", "")).netloc
            or analysis.get("site_metadata", {}).get("domain", "unknown")
        )
        ns = analysis.get("nameservers")
        row = {
            "domain":              domain,
            "url":                 analysis.get("url"),
            "analysed_at":         analysis.get("analysed_at"),
            "score":               int(analysis.get("score", 0)),
            "status":              analysis.get("status"),
            "verdict":             analysis.get("verdict"),
            "signals":             analysis.get("signals"),
            "whois":               analysis.get("whois"),
            "ssl_certificate":     analysis.get("ssl_certificate"),
            "site_metadata":       analysis.get("site_metadata"),
            "risk_classification": analysis.get("risk_classification"),
            "recommendation":      analysis.get("recommendation"),
            "dns":                 analysis.get("dns"),
            "nameservers":         _json.dumps(ns) if ns else None,
        }
        supabase_service.table("whois_phish").insert(row).execute()
    except Exception as e:
        print(f"[whois_phish upload error] {e}")


@router.post("/scan")
async def scan_url(req: ScanRequest, user=Depends(verify_supabase_jwt)):
    user_id = user.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid auth token")

    _check_enterprise_access(user_id)

    domain = req.domain or urlparse(req.url).netloc or req.url
    analysis = await run_scan(url=req.url, domain=domain, model=req.model)

    _upload_to_whois_phish(analysis)

    return analysis


@router.get("/scan/models")
def list_scan_models():
    """List all supported phishing-scan models."""
    return {
        "models": [{"model": m, "provider": p} for m, p in SUPPORTED_MODELS.items()]
    }
