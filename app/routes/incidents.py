from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


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
    tabUrl: str
    tabTitle: str
    maskedSecrets: List[MaskedSecret]
    timestamp: str
    extensionVersion: str
    # Optional top-level phishing fields
    type: Optional[str] = None      # 'phishing' | 'url_visit'
    domain: Optional[str] = None    # already present in tabUrl; kept for convenience
    # Full layer breakdown — written to the existing extra jsonb column
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

    if not data.maskedSecrets:
        raise HTTPException(
            status_code=400,
            detail="maskedSecrets cannot be empty"
        )

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

        row = {
            "user_id":           user_id,
            "user_email":        user_email,
            "browser_id":        data.browserId,
            "tab_url":           data.tabUrl,   # full URL already contains domain
            "tab_title":         data.tabTitle,
            "secret_type":       secret.type,
            "severity":          secret.severity,
            "masked_preview":    secret.maskedPreview,
            "action":            secret.action,
            "timestamp":         data.timestamp,
            "extension_version": data.extensionVersion,
        }

        # Only write extra when there is something to store
        if extra_payload:
            row["extra"] = extra_payload

        rows.append(row)

    try:
        res = supabase.table("incidents").insert(rows).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log incident: {str(e)}")

    return {
        "success": True,
        "inserted": len(res.data) if res.data else 0
    }
