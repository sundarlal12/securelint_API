from fastapi import APIRouter, Depends, HTTPException
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt
from datetime import datetime

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# @router.get("/subscription")
# def get_subscription(user=Depends(verify_supabase_jwt)):
#     user_id = user["sub"]

#     res = (
#         supabase
#         .table("user_subscriptions")
#         .select("*")
#         .eq("user_id", user_id)
#         .single()
#         .execute()
#     )

#     if not res.data:
#         raise HTTPException(404, "Subscription not found")

#     sub = res.data

#     is_active = (
#         sub["status"] == "active" or
#         (sub["status"] == "trial" and
#          sub["trial_ends_at"] and
#          datetime.utcnow() < datetime.fromisoformat(sub["trial_ends_at"]))
#     )

#     return {
#         "plan": sub["plan_id"],
#         "status": sub["status"],
#         "active": is_active,
#         "trial_ends_at": sub["trial_ends_at"],
#         "current_period_end": sub["current_period_end"]
#     }


@router.get("/subscription")
def get_subscription(user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    res = (
        supabase
        .table("user_subscriptions")
        .select("*")
        .eq("user_id", user_id)
        .execute()
    )

    if not res.data:
        # default free plan if not created yet
        return {
            "plan": "free",
            "status": "active",
            "active": True,
            "trial_ends_at": None,
            "current_period_end": None
        }

    sub = res.data[0]

    return {
        "plan": sub["plan_id"],
        "status": sub["status"],
        "active": sub["status"] in ("active", "trial"),
        "trial_ends_at": sub["trial_ends_at"],
        "current_period_end": sub["current_period_end"]
    }
