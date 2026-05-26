from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
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


class IncidentRequest(BaseModel):
    browserId: str
    tabUrl: str
    tabTitle: str
    maskedSecrets: List[MaskedSecret]
    timestamp: str
    extensionVersion: str


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
        rows.append({
            "user_id": user_id,
            "user_email": user_email,
            "browser_id": data.browserId,
            "tab_url": data.tabUrl,
            "tab_title": data.tabTitle,
            "secret_type": secret.type,
            "severity": secret.severity,
            "masked_preview": secret.maskedPreview,
            "action": secret.action,
            "timestamp": data.timestamp,
            "extension_version": data.extensionVersion,
        })

    try:
        res = supabase.table("incidents").insert(rows).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log incident: {str(e)}")

    return {
        "success": True,
        "inserted": len(res.data) if res.data else 0
    }
