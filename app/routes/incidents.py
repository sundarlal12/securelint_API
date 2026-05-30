from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from supabase import create_client
import os
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Service-role client bypasses RLS — needed to query organizations table
_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase

EXTENSION_INCIDENT_TYPE = "extension_type"

# Free/consumer email domains — never treated as business domains
_FREE_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "aol.com", "live.com", "msn.com", "me.com",
    "mail.com", "inbox.com", "yandex.com", "zoho.com",
}


def _get_org_id_by_email_domain(user_email: str) -> Optional[str]:
    """
    Looks up the organizations table for an active org whose org_domains
    array contains the domain portion of user_email.
    Returns org id (str) if found and active (status=true), otherwise None.
    """
    if not user_email or "@" not in user_email:
        return None

    domain = user_email.split("@", 1)[1].lower().strip()

    if domain in _FREE_DOMAINS:
        return None

    try:
        res = (
            supabase_service
            .table("organizations")
            .select("id, status")
            .filter("org_domains", "cs", f'{{"{domain}"}}')
            .limit(1)
            .execute()
        )
    except Exception:
        return None

    if not res.data:
        return None

    org = res.data[0]

    if org.get("status") is not True:
        return None

    return str(org["id"])


def _build_base_row(
    user_id: str,
    user_email: str,
    data: "IncidentRequest",
    org_id: Optional[str],
    *,
    secret_type: str,
    severity: str,
    masked_preview: str,
    action: str,
    tab_url: str,
    tab_title: str,
    timestamp: str,
    extra: Optional[Dict[str, Any]] = None,
    extensions: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    row: Dict[str, Any] = {
        "user_id":           user_id,
        "user_email":        user_email,
        "browser_id":        data.browserId,
        "extension_version": data.extensionVersion,
        "secret_type":       secret_type,
        "severity":          severity,
        "masked_preview":    masked_preview,
        "action":            action,
        "tab_url":           tab_url,
        "tab_title":         tab_title,
        "timestamp":         timestamp,
    }
    if data.browserInfo:
        row["browser_info"] = data.browserInfo
    if org_id:
        row["org_id"] = org_id
    if extra:
        row["extra"] = extra
    if extensions:
        row["extensions"] = extensions
    return row


class MaskedSecret(BaseModel):
    type: str
    severity: str
    maskedPreview: str
    action: str
    status: Optional[str] = None   # 'safe' | 'suspicious' | 'unsafe' | 'danger'
    score: Optional[int] = None    # 0–100 trust score


class IncidentRequest(BaseModel):
    browserId: str
    extensionVersion: str
    browserInfo: Optional[Dict[str, Any]] = None
    tabUrl: Optional[str] = None
    tabTitle: Optional[str] = None
    timestamp: Optional[str] = None
    maskedSecrets: Optional[List[MaskedSecret]] = None
    type: Optional[str] = None      # 'phishing' | 'url_visit' | 'extension_type' | etc.
    domain: Optional[str] = None
    extensions: Optional[Dict[str, Any]] = None
    extra: Optional[Dict[str, Any]] = None


@router.post("/incidents")
def create_incident(data: IncidentRequest, user=Depends(verify_supabase_jwt)):
    user_id = user.get("sub")
    user_email = user.get("email")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail={"success": False, "inserted": 0, "detail": "Auth token is missing or invalid: no user ID found"},
        )
    if not user_email:
        raise HTTPException(
            status_code=401,
            detail={"success": False, "inserted": 0, "detail": "Auth token is missing or invalid: no email found in token"},
        )

    # Gate: only active enterprise subscribers may log incidents
    try:
        sub_res = (
            supabase_service
            .table("user_subscriptions")
            .select("plan_id, status")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail={"success": False, "inserted": 0, "detail": "Failed to verify subscription"},
        )

    if not sub_res.data:
        raise HTTPException(
            status_code=403,
            detail={"success": False, "inserted": 0, "detail": "No subscription found. Access denied."},
        )

    sub = sub_res.data[0]
    if sub.get("plan_id") != "enterprise" or sub.get("status") != "active":
        raise HTTPException(
            status_code=403,
            detail={"success": False, "inserted": 0, "detail": "Active enterprise subscription required to log incidents."},
        )

    # Resolve org_id from email domain — stamped on row for dashboard filtering.
    org_id = _get_org_id_by_email_domain(user_email)

    # ── extension_type incident ──────────────────────────────────────────────
    if data.type == EXTENSION_INCIDENT_TYPE:
        row = _build_base_row(
            user_id=user_id,
            user_email=user_email,
            data=data,
            org_id=org_id,
            secret_type=EXTENSION_INCIDENT_TYPE,
            severity="info",
            masked_preview="extension_report",
            action="sync",
            tab_url=data.tabUrl or "chrome://extensions/",
            tab_title=data.tabTitle or "extension_report",
            timestamp=data.timestamp or "",
            extensions=data.extensions,
        )

        try:
            res = supabase_service.table("incidents").insert([row]).execute()
        except Exception as e:
            raise HTTPException(
                status_code=500,
                detail={"success": False, "inserted": 0, "detail": f"Failed to log incident: {str(e)}"},
            )

        return {
            "success": True,
            "inserted": len(res.data) if res.data else 0,
        }

    # ── all other incident types (secret_mask, phishing, url_visit, dlp, email, etc.)
    if not data.tabUrl:
        raise HTTPException(
            status_code=400,
            detail={"success": False, "inserted": 0, "detail": "tabUrl is required for this incident type"},
        )
    if not data.tabTitle:
        raise HTTPException(
            status_code=400,
            detail={"success": False, "inserted": 0, "detail": "tabTitle is required for this incident type"},
        )
    if not data.timestamp:
        raise HTTPException(
            status_code=400,
            detail={"success": False, "inserted": 0, "detail": "timestamp is required for this incident type"},
        )
    if not data.maskedSecrets:
        raise HTTPException(
            status_code=400,
            detail={"success": False, "inserted": 0, "detail": "maskedSecrets cannot be empty"},
        )

    rows = []
    for secret in data.maskedSecrets:
        extra_payload: Dict[str, Any] = dict(data.extra) if data.extra else {}
        if secret.status is not None:
            extra_payload["site_status"] = secret.status
        if secret.score is not None:
            extra_payload["site_score"] = secret.score

        row = _build_base_row(
            user_id=user_id,
            user_email=user_email,
            data=data,
            org_id=org_id,
            secret_type=secret.type,
            severity=secret.severity,
            masked_preview=secret.maskedPreview,
            action=secret.action,
            tab_url=data.tabUrl,
            tab_title=data.tabTitle,
            timestamp=data.timestamp,
            extra=extra_payload or None,
        )
        rows.append(row)

    try:
        res = supabase_service.table("incidents").insert(rows).execute()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"success": False, "inserted": 0, "detail": f"Failed to log incident: {str(e)}"},
        )

    return {
        "success": True,
        "inserted": len(res.data) if res.data else 0,
    }
