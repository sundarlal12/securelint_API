import os
from fastapi import APIRouter, Depends
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt
from app.core.plan_features import build_settings_row, _get_all_features, _STATIC_FIELDS

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase


def _mask_all_features(settings: dict, supabase_client) -> dict:
    """
    Returns a copy of settings with all boolean feature flags set to False.
    Used when subscription is inactive — user can see the structure but not use features.
    Non-boolean fields (masking_style, site_exclusions, Plans, etc.) are preserved.
    """
    boolean_cols = _get_all_features(supabase_client)
    masked = dict(settings)
    for col in boolean_cols:
        if col in masked:
            masked[col] = False
    return masked


@router.get("/settings")
def get_settings(user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    # ── Fetch user_settings row ───────────────────────────────────────────────
    res = supabase_service.table("user_settings").select("*").eq("user_id", user_id).execute()

    if not res.data:
        # No row yet — create one from plan_settings (all-False defaults via plan_features)
        try:
            sub_res = supabase_service.table("user_subscriptions").select("plan_id").eq("user_id", user_id).limit(1).execute()
            plan_id = sub_res.data[0]["plan_id"] if sub_res.data else "free"
        except Exception:
            plan_id = "free"

        default_row = build_settings_row(user_id, plan_id, supabase_service)
        try:
            supabase_service.table("user_settings").insert(default_row).execute()
        except Exception:
            pass
        settings = default_row
    else:
        settings = res.data[0]

    # ── Check subscription status ─────────────────────────────────────────────
    is_active = False
    try:
        sub_res = (
            supabase_service
            .table("user_subscriptions")
            .select("status")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        if sub_res.data:
            is_active = sub_res.data[0].get("status") == "active"
    except Exception:
        pass

    # ── Gate: return real settings only if subscription is active ─────────────
    if not is_active:
        return _mask_all_features(settings, supabase_service)

    return settings


@router.put("/settings")
def update_settings(updates: dict, user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    # Only allow columns that exist in user_settings
    boolean_cols = set(_get_all_features(supabase_service))
    non_boolean_allowed = {"masking_style", "site_exclusions", "waf_social_domain",
                           "enterprise_email_domains", "email_dlp_domain",
                           "email_dlp_action", "IT_mail", "Plans"}
    allowed_fields = boolean_cols | non_boolean_allowed

    clean_updates = {k: v for k, v in updates.items() if k in allowed_fields}

    if not clean_updates:
        return {"success": False, "message": "No valid settings fields provided"}

    # Ensure row exists
    exists = supabase.table("user_settings").select("user_id").eq("user_id", user_id).execute()
    if not exists.data:
        supabase.table("user_settings").insert({"user_id": user_id}).execute()

    supabase.table("user_settings").update(clean_updates).eq("user_id", user_id).execute()

    return {"success": True, "updated": clean_updates}
