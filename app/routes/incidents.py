from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from supabase import create_client
import os
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Service-role client bypasses RLS — used for org_id lookups across tables
_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase


def _get_org_id_for_enterprise_user(user_id: str) -> Optional[str]:
    """
    Returns org_id if the user is on an active enterprise plan and is a member
    of an organization. Returns None for free/pro users — no error is raised
    because incidents are valid for all plan types.
    """
    sub_res = (
        supabase_service
        .table("user_subscriptions")
        .select("plan_id, status")
        .eq("user_id", user_id)
        .execute()
    )

    if not sub_res.data:
        return None

    sub = sub_res.data[0]
    if sub.get("plan_id") != "enterprise" or sub.get("status") != "active":
        return None

    org_res = (
        supabase_service
        .table("organization_members")
        .select("org_id")
        .eq("user_id", user_id)
        .execute()
    )

    if not org_res.data:
        return None

    return org_res.data[0].get("org_id")


EXTENSION_INCIDENT_TYPE = "extension_type"


class MaskedSecret(BaseModel):
    type: str
    severity: str
    maskedPreview: str
    action: str
    # Phishing / site-safety fields — stored inside extra, not as separate columns
    status: Optional[str] = None   # 'safe' | 'suspicious' | 'unsafe' | 'danger'
    score: Optional[int] = None    # 0–100 trust score


class IncidentRequest(BaseModel):
    browserId: str
    extensionVersion: str
    # Required for all types except extension_type
    tabUrl: Optional[str] = None
    tabTitle: Optional[str] = None
    timestamp: Optional[str] = None
    maskedSecrets: Optional[List[MaskedSecret]] = None
    # Incident type — drives routing logic
    type: Optional[str] = None      # 'phishing' | 'url_visit' | 'extension_type'
    domain: Optional[str] = None    # already present in tabUrl; kept for convenience
    # extension_type payloads: permissions, metadata, etc. → extensions jsonb column
    extensions: Optional[Dict[str, Any]] = None
    # Full layer breakdown for non-extension types → extra jsonb column
    extra: Optional[Dict[str, Any]] = None


@router.post("/incidents")
def create_incident(data: IncidentRequest, user=Depends(verify_supabase_jwt)):
    user_id = user.get("sub")
    user_email = user.get("email")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Auth token is missing or invalid: no user ID found"
        )

    if not user_email:
        raise HTTPException(
            status_code=401,
            detail="Auth token is missing or invalid: no email found in token"
        )

    # Resolve org_id for enterprise users; None for free/pro users
    org_id = _get_org_id_for_enterprise_user(user_id)

    # ── extension_type incident ──────────────────────────────────────────────
    if data.type == EXTENSION_INCIDENT_TYPE:
        row: Dict[str, Any] = {
            "user_id":           user_id,
            "user_email":        user_email,
            "browser_id":        data.browserId,
            "extension_version": data.extensionVersion,
            "secret_type":       EXTENSION_INCIDENT_TYPE,
            "tab_url":           data.tabUrl   or "chrome://extensions/",
            "tab_title":         data.tabTitle or "extension_report",
            "timestamp":         data.timestamp or "",
            "severity":          "info",
            "masked_preview":    "extension_report",
            "action":            "sync",
        }

        if org_id:
            row["org_id"] = org_id

        # Store all extension-specific data (permissions, metadata, etc.)
        if data.extensions:
            row["extensions"] = data.extensions

        try:
            res = supabase.table("incidents").insert([row]).execute()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to log incident: {str(e)}")

        return {
            "success": True,
            "inserted": len(res.data) if res.data else 0,
        }

    # ── all other incident types ─────────────────────────────────────────────
    if not data.tabUrl:
        raise HTTPException(status_code=400, detail="tabUrl is required for this incident type")
    if not data.tabTitle:
        raise HTTPException(status_code=400, detail="tabTitle is required for this incident type")
    if not data.timestamp:
        raise HTTPException(status_code=400, detail="timestamp is required for this incident type")
    if not data.maskedSecrets:
        raise HTTPException(status_code=400, detail="maskedSecrets cannot be empty")

    rows = []
    for secret in data.maskedSecrets:
        # Build the extra jsonb payload.
        # Start with whatever the extension sent in data.extra, then surface the
        # site_status and site_score from maskedSecrets into it so they are always
        # present in the single extra column — no new table columns needed.
        extra_payload: Dict[str, Any] = dict(data.extra) if data.extra else {}

        if secret.status is not None:
            extra_payload["site_status"] = secret.status
        if secret.score is not None:
            extra_payload["site_score"] = secret.score

        incident_row: Dict[str, Any] = {
            "user_id":           user_id,
            "user_email":        user_email,
            "browser_id":        data.browserId,
            "tab_url":           data.tabUrl,
            "tab_title":         data.tabTitle,
            "secret_type":       secret.type,
            "severity":          secret.severity,
            "masked_preview":    secret.maskedPreview,
            "action":            secret.action,
            "timestamp":         data.timestamp,
            "extension_version": data.extensionVersion,
        }

        # Stamp org_id only for enterprise users so admin dashboard can filter by org
        if org_id:
            incident_row["org_id"] = org_id

        # Only write extra when there is something to store
        if extra_payload:
            incident_row["extra"] = extra_payload

        rows.append(incident_row)

    try:
        res = supabase.table("incidents").insert(rows).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log incident: {str(e)}")

    return {
        "success": True,
        "inserted": len(res.data) if res.data else 0,
    }
