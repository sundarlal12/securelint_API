

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

class AuthRequest(BaseModel):
    email: str
    password: str
    browser_id: str

class RefreshRequest(BaseModel):
    refresh_token: str


# @router.post("/signup")
# def signup(data: AuthRequest):
#     res = supabase.auth.sign_up({
#         "email": data.email,
#         "password": data.password
#     })

#     if res.user is None:
#         raise HTTPException(
#             status_code=409,
#             detail="User already exists. Please sign in."
#         )

#     user_id = res.user.id

#     # register browser
#     supabase.table("user_devices").insert({
#         "user_id": user_id,
#         "browser_id": data.browser_id
#     }).execute()

#     # auto-create FREE subscription
#     supabase.table("user_subscriptions").insert({
#         "user_id": user_id,
#         "plan_id": "free",
#         "status": "active"
#     }).execute()

#     # auto-create default settings
#     supabase.table("user_settings").insert({
#         "user_id": user_id
#     }).execute()

#     if res.session is None:
#         return {
#             "success": True,
#             "message": "Signup successful. Please verify your email."
#         }

#     return {
#         "success": True,
#         "access_token": res.session.access_token,
#         "refresh_token": res.session.refresh_token
#     }


@router.post("/signup")
def signup(data: AuthRequest):
    try:
        res = supabase.auth.sign_up({
            "email": data.email,
            "password": data.password
        })
    except Exception as e:
        msg = str(e).lower()

        # Supabase duplicate user error
        if "already registered" in msg or "user already exists" in msg:
            raise HTTPException(
                status_code=409,
                detail={
                    "error": 1,
                    "message": "Already existing user"
                }
            )

        # any other signup error
        raise HTTPException(
            status_code=400,
            detail={
                "error": 1,
                "message": "Signup failed"
            }
        )

    # safety check (rare but good practice)
    if res.user is None:
        raise HTTPException(
            status_code=409,
            detail={
                "error": 1,
                "message": "Already existing user"
            }
        )

    user_id = res.user.id

    # register browser (ignore duplicates safely)
    supabase.table("user_devices").insert({
        "user_id": user_id,
        "browser_id": data.browser_id
    }).execute()

    # auto-create FREE subscription
    supabase.table("user_subscriptions").insert({
        "user_id": user_id,
        "plan_id": "free",
        "status": "active"
    }).execute()

    # auto-create default settings
    supabase.table("user_settings").insert({
        "user_id": user_id
    }).execute()

    if res.session is None:
        return {
            "success": True,
            "message": "Signup successful. Please verify your email."
        }

    return {
        "success": True,
        "access_token": res.session.access_token,
        "refresh_token": res.session.refresh_token
    }
 

from fastapi import HTTPException

@router.post("/signin")
def signin(data: AuthRequest):
    # 1️⃣ Authenticate user (email + password only)
    try:
        res = supabase.auth.sign_in_with_password({
            "email": data.email,
            "password": data.password
        })
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not res or not res.user or not res.session:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    user_id = res.user.id

    # 2️⃣ Check if browser already registered
    device = (
        supabase
        .table("user_devices")
        .select("id")
        .eq("user_id", user_id)
        .eq("browser_id", data.browser_id)
        .execute()
    )

    # 3️⃣ If browser not registered → register it
    if not device.data:
        supabase.table("user_devices").insert({
            "user_id": user_id,
            "browser_id": data.browser_id
        }).execute()

    # 4️⃣ Successful login response
    return {
        "success": True,
        "access_token": res.session.access_token,
        "refresh_token": res.session.refresh_token
    }


# @router.post("/refresh")
# def refresh_token(data: RefreshRequest):
#     try:
#         res = supabase.auth.refresh_session({
#             "refresh_token": data.refresh_token
#         })
#     except Exception:
#         raise HTTPException(
#             status_code=401,
#             detail="Invalid refresh token"
#         )

#     if not res or not res.session:
#         raise HTTPException(
#             status_code=401,
#             detail="Failed to refresh session"
#         )

#     return {
#         "success": True,
#         "access_token": res.session.access_token,
#         "refresh_token": res.session.refresh_token
#     }
@router.post("/refresh")
def refresh_token(data: RefreshRequest):
    try:
        res = supabase.auth.refresh_session(data.refresh_token)
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    if not res or not res.session:
        raise HTTPException(
            status_code=401,
            detail="Invalid refresh token"
        )

    return {
        "success": True,
        "access_token": res.session.access_token,
        "refresh_token": res.session.refresh_token
    }