from fastapi import APIRouter, HTTPException, Header
from supabase import create_client
from typing import Optional
import os
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_anon    = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase_anon


def _get_user_id(token: Optional[str]) -> str:
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Authentication required."})
    try:
        user = supabase_anon.auth.get_user(token[7:])
        return str(user.user.id)
    except Exception:
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid or expired token."})


# ── GET /api/user/me ──────────────────────────────────────────────────────────
@router.get("/user/me")
def get_user_me(authorization: Optional[str] = Header(None)):
    user_id = _get_user_id(authorization)

    # Auth user details
    try:
        auth_user = supabase_service.auth.admin.get_user_by_id(user_id)
        email     = auth_user.user.email or ""
        meta      = auth_user.user.user_metadata or {}
        full_name = meta.get("full_name") or meta.get("name") or ""
        created_at = str(auth_user.user.created_at or "")
    except Exception:
        email, full_name, created_at = "", "", ""

    # Subscription — read from user_subscriptions; fall back to user_settings.Plans
    plan_id     = "free"
    plan_status = "inactive"
    try:
        sub_res = supabase_service.table("user_subscriptions").select("plan_id, status").eq("user_id", user_id).execute()
        if sub_res.data:
            sub         = sub_res.data[0]
            plan_id     = sub.get("plan_id") or "free"
            plan_status = sub.get("status")  or "inactive"
        else:
            # No subscription row — check user_settings.Plans as fallback
            try:
                st_res  = supabase_service.table("user_settings").select("Plans").eq("user_id", user_id).execute()
                if st_res.data and st_res.data[0].get("Plans"):
                    plan_id = st_res.data[0]["Plans"]
            except Exception:
                pass
    except Exception:
        pass

    # Plan details
    try:
        plan_res  = supabase_service.table("plans").select("id, name, price_monthly").eq("id", plan_id).execute()
        plan_info = plan_res.data[0] if plan_res.data else {"id": plan_id, "name": plan_id.capitalize(), "price_monthly": 0}
        if plan_info.get("id") == "free":
            plan_info["name"] = "Beginner"
    except Exception:
        plan_info = {"id": plan_id, "name": plan_id.capitalize(), "price_monthly": 0}

    # User settings
    try:
        settings_res = supabase_service.table("user_settings").select("*").eq("user_id", user_id).execute()
        settings     = settings_res.data[0] if settings_res.data else {}
    except Exception:
        settings = {}

    return {
        "error":       0,
        "user_id":     user_id,
        "email":       email,
        "full_name":   full_name,
        "created_at":  created_at,
        "plan":        plan_info,
        "plan_status": plan_status,
        "settings":    settings,
    }


# ── PATCH /api/user/me ────────────────────────────────────────────────────────
from pydantic import BaseModel

class UpdateProfileRequest(BaseModel):
    full_name: Optional[str] = None

@router.patch("/user/me")
def update_user_me(body: UpdateProfileRequest, authorization: Optional[str] = Header(None)):
    user_id = _get_user_id(authorization)
    try:
        if body.full_name is not None:
            supabase_service.auth.admin.update_user_by_id(user_id, {"user_metadata": {"full_name": body.full_name}})
        return {"error": 0, "success": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(e)})
