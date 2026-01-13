# from fastapi import APIRouter, HTTPException, Depends

# from app.core.supabase_jwt import verify_supabase_jwt
# import os

# from supabase import create_client
# from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

# supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# router = APIRouter()

# supabase = create_client(
#     os.getenv("NEXT_PUBLIC_SUPABASE_URL"),
#     os.getenv("NEXT_PUBLIC_SUPABASE_ANON_KEY")
# )

# @router.post("/signup")
# def signup(email: str, password: str, browser_id: str):
#     res = supabase.auth.sign_up({
#         "email": email,
#         "password": password
#     })

#     if res.user is None:
#         raise HTTPException(status_code=400, detail="Signup failed")

#     supabase.table("user_devices").insert({
#         "user_id": res.user.id,
#         "browser_id": browser_id
#     }).execute()

#     return {
#         "access_token": res.session.access_token,
#         "refresh_token": res.session.refresh_token
#     }

# @router.post("/signin")
# def signin(email: str, password: str, browser_id: str):
#     res = supabase.auth.sign_in_with_password({
#         "email": email,
#         "password": password
#     })

#     if res.user is None:
#         raise HTTPException(status_code=401, detail="Invalid credentials")

#     existing = (
#         supabase
#         .table("user_devices")
#         .select("id")
#         .eq("user_id", res.user.id)
#         .eq("browser_id", browser_id)
#         .execute()
#     )

#     if not existing.data:
#         raise HTTPException(
#             status_code=403,
#             detail="This account is not allowed on this browser"
#         )

#     return {
#         "access_token": res.session.access_token,
#         "refresh_token": res.session.refresh_token
#     }

# @router.get("/me")
# def me(user=Depends(verify_supabase_jwt)):
#     return {
#         "user_id": user["sub"],
#         "email": user.get("email")
#     }


# from fastapi import APIRouter, HTTPException, Depends
# from supabase import create_client
# from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
# from app.core.supabase_jwt import verify_supabase_jwt
# import traceback

# router = APIRouter()

# supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# # ---------------- SIGNUP ----------------
# @router.post("/signup")
# def signup(email: str, password: str, browser_id: str):
#     try:
#         res = supabase.auth.sign_up({
#             "email": email,
#             "password": password
#         })

#         # 🚨 Supabase error handling
#         if res.user is None:
#             raise HTTPException(
#                 status_code=400,
#                 detail=str(res)
#             )

#         # Store browser/device
#         supabase.table("user_devices").insert({
#             "user_id": res.user.id,
#             "browser_id": browser_id
#         }).execute()

#         return {
#             "access_token": res.session.access_token,
#             "refresh_token": res.session.refresh_token
#         }

#     except Exception as e:
#         print("SIGNUP ERROR:")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # ---------------- SIGNIN ----------------
# @router.post("/signin")
# def signin(email: str, password: str, browser_id: str):
#     try:
#         res = supabase.auth.sign_in_with_password({
#             "email": email,
#             "password": password
#         })

#         if res.user is None:
#             raise HTTPException(
#                 status_code=401,
#                 detail="Invalid email or password"
#             )

#         # Check browser binding
#         existing = (
#             supabase
#             .table("user_devices")
#             .select("id")
#             .eq("user_id", res.user.id)
#             .eq("browser_id", browser_id)
#             .execute()
#         )

#         if not existing.data:
#             raise HTTPException(
#                 status_code=403,
#                 detail="This browser is not registered"
#             )

#         return {
#             "access_token": res.session.access_token,
#             "refresh_token": res.session.refresh_token
#         }

#     except Exception as e:
#         print("SIGNIN ERROR:")
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))


# # ---------------- TEST ----------------
# @router.get("/me")
# def me(user=Depends(verify_supabase_jwt)):
#     return {
#         "user_id": user["sub"],
#         "email": user.get("email")
#     }



# from fastapi import APIRouter, HTTPException, Depends
# from pydantic import BaseModel
# from supabase import create_client
# from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
# from app.core.supabase_jwt import verify_supabase_jwt

# router = APIRouter()
# supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# # ---------- REQUEST MODELS ----------
# class AuthRequest(BaseModel):
#     email: str
#     password: str
#     browser_id: str


# # ---------- SIGNUP ----------
# @router.post("/signup")
# def signup(data: AuthRequest):
#     res = supabase.auth.sign_up({
#         "email": data.email,
#         "password": data.password
#     })

#     if res.user is None:
#         raise HTTPException(400, "Signup failed")

#     # register browser
#     supabase.table("user_devices").insert({
#         "user_id": res.user.id,
#         "browser_id": data.browser_id
#     }).execute()

#     # email confirmation ON → no session
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


# # ---------- SIGNIN ----------
# @router.post("/signin")
# def signin(data: AuthRequest):
#     res = supabase.auth.sign_in_with_password({
#         "email": data.email,
#         "password": data.password
#     })

#     if res.user is None:
#         raise HTTPException(401, "Invalid credentials")

#     # verify browser
#     device = (
#         supabase
#         .table("user_devices")
#         .select("id")
#         .eq("user_id", res.user.id)
#         .eq("browser_id", data.browser_id)
#         .execute()
#     )

#     if not device.data:
#         raise HTTPException(403, "Browser not registered")

#     return {
#         "success": True,
#         "access_token": res.session.access_token,
#         "refresh_token": res.session.refresh_token
#     }



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
    
# @router.post("/signin")
# def signin(data: AuthRequest):
#     res = supabase.auth.sign_in_with_password({
#         "email": data.email,
#         "password": data.password
#     })

#     if res.user is None:
#         raise HTTPException(401, "Invalid credentials")

#     device = (
#         supabase
#         .table("user_devices")
#         .select("id")
#         .eq("user_id", res.user.id)
#         .eq("browser_id", data.browser_id)
#         .execute()
#     )

#     if not device.data:
#         raise HTTPException(403, "Browser not registered")

#     return {
#         "success": True,
#         "access_token": res.session.access_token,
#         "refresh_token": res.session.refresh_token
#     }

@router.post("/signin")
def signin(data: AuthRequest):
    try:
        res = supabase.auth.sign_in_with_password({
            "email": data.email,
            "password": data.password
        })
    except Exception as e:
        # Invalid email / password
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    if not res or not res.user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    device = (
        supabase
        .table("user_devices")
        .select("id")
        .eq("user_id", res.user.id)
        .eq("browser_id", data.browser_id)
        .execute()
    )

    if not device.data:
        raise HTTPException(
            status_code=403,
            detail="Browser not registered"
        )

    return {
        "success": True,
        "access_token": res.session.access_token,
        "refresh_token": res.session.refresh_token
    }
