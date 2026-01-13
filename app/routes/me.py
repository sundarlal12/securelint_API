# from fastapi import APIRouter, Depends
# from supabase import create_client
# from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
# from app.core.supabase_jwt import verify_supabase_jwt

# router = APIRouter()
# supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# @router.get("/me")
# def me(user=Depends(verify_supabase_jwt)):
#     user_id = user["sub"]

#     sub = (
#         supabase
#         .table("user_subscriptions")
#         .select("plan_id, status, trial_ends_at, current_period_end")
#         .eq("user_id", user_id)
#         .single()
#         .execute()
#     )

#     return {
#         "user_id": user_id,
#         "email": user.get("email"),
#         "subscription": sub.data
#     }

from fastapi import APIRouter, Depends
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

@router.get("/me")
def me(user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    sub = (
        supabase
        .table("user_subscriptions")
        .select("plan_id, status, trial_ends_at, current_period_end")
        .eq("user_id", user_id)
        .execute()
    )

    subscription = sub.data[0] if sub.data else None

    return {
        "user_id": user_id,
        "email": user.get("email"),
        "subscription": subscription
    }
