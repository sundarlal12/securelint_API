import os
from fastapi import APIRouter, Depends
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt
from app.routes.settings import _mask_all_features, _ARRAY_COLUMNS

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase


@router.get("/me")
def me(user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    # ── Subscription ──────────────────────────────────────────────────────────
    sub_res = (
        supabase_service
        .table("user_subscriptions")
        .select("plan_id, status, trial_ends_at, current_period_end")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    subscription = sub_res.data[0] if sub_res.data else None
    is_active    = subscription.get("status") == "active" if subscription else False
    plan_id      = subscription.get("plan_id", "free")   if subscription else "free"

    # ── Settings ──────────────────────────────────────────────────────────────
    settings_res = (
        supabase_service
        .table("user_settings")
        .select("*")
        .eq("user_id", user_id)
        .limit(1)
        .execute()
    )
    settings = settings_res.data[0] if settings_res.data else {}

    # Gate: mask all boolean features when subscription is inactive
    if not is_active:
        settings = _mask_all_features(settings, supabase_service)

    return {
        "user_id":             user_id,
        "email":               user.get("email"),
        "subscription":        subscription,
        "subscription_active": is_active,
        "plan_id":             plan_id,
        "settings":            settings,
    }
