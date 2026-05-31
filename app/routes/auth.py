

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from supabase import create_client
from typing import Optional
import os, uuid, hmac, hashlib, base64, time
import resend
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

# Google OAuth verification
_GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "970630889678-7aojvvhm0umigok9l7ipsvkrkj1gs3k9.apps.googleusercontent.com")
_GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")

_RESEND_KEY             = os.getenv("RESEND_API_KEY", "")
_RESEND_SIGNUP_TEMPLATE = os.getenv("RESEND_SIGNUP_TEMPLATE_ID", "d4eb4d59-26a4-40c4-af85-82dfa0ce1554")
_BASE_URL               = os.getenv("BASE_URL", "https://securelint.in")


def _send_welcome_email(email: str, password: str, full_name: str = "") -> None:
    """
    Send welcome email via Resend template.
    Template variables: {{email}}, {{temp_password}}
    Best-effort — never raises, never blocks signup.
    """
    if not _RESEND_KEY:
        print("[welcome-email] skipped — RESEND_API_KEY not set")
        return
    if not _RESEND_SIGNUP_TEMPLATE:
        print("[welcome-email] skipped — RESEND_SIGNUP_TEMPLATE_ID not set")
        return
    try:
        resend.api_key = _RESEND_KEY
        result = resend.Emails.send({
            "from": "SecureLint <noreply@securelint.in>",
            "to":   email,
            "template": {
                "id": _RESEND_SIGNUP_TEMPLATE,
                "variables": {
                    "email":         email,
                    "temp_password": password,
                },
            },
        })
        print(f"[welcome-email] sent to {email} → {result}")
    except Exception as e:
        print(f"[welcome-email] FAILED for {email}: {e}")

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Service-role client bypasses RLS — used for admin/org lookups
_SERVICE_KEY     = os.getenv("SUPABASE_SERVICE_KEY", "")
_SUPERADMIN_KEY  = os.getenv("SUPERADMIN_KEY", "")          # protects invite generation
_INVITE_SECRET   = os.getenv("INVITE_SECRET", _SERVICE_KEY) # signs invite tokens
_INVITE_TTL_SECS = int(os.getenv("INVITE_TTL_SECS", "604800"))  # default 7 days

supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase


# ── Invite token helpers ──────────────────────────────────────────────────────

def _make_invite_token(email: str, ttl_secs: Optional[int] = None) -> str:
    """
    Returns a URL-safe token: base64(email:expiry:hmac)
    The token encodes the target email and expiry so it can be validated
    without any database lookup.
    """
    expiry = int(time.time()) + (ttl_secs if ttl_secs is not None else _INVITE_TTL_SECS)
    payload = f"{email.lower().strip()}:{expiry}"
    sig = hmac.new(_INVITE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    raw = f"{payload}:{sig}"
    return base64.urlsafe_b64encode(raw.encode()).decode()

def _verify_invite_token(token: str, email: str) -> None:
    """
    Raises HTTPException if the token is invalid, expired, or not for this email.
    """
    if not _INVITE_SECRET:
        raise HTTPException(status_code=500, detail={"error": 1, "message": "Server misconfiguration: INVITE_SECRET not set."})
    try:
        raw     = base64.urlsafe_b64decode(token.encode()).decode()
        parts   = raw.split(":")
        if len(parts) != 3:
            raise ValueError("bad format")
        tok_email, expiry_str, sig = parts
        expiry = int(expiry_str)
    except Exception:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Invalid invite code."})

    # Check expiry
    if time.time() > expiry:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Invite code has expired."})

    # Verify signature
    payload      = f"{tok_email}:{expiry_str}"
    expected_sig = hmac.new(_INVITE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Invalid invite code."})

    # Verify it was issued for this email (case-insensitive)
    if tok_email != email.lower().strip():
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Invite code is not valid for this email address."})


# ── Superadmin: generate invite ───────────────────────────────────────────────

class InviteCreateRequest(BaseModel):
    email: str
    ttl_days: Optional[int] = 7   # override default TTL

@router.post("/superadmin/create-invite")
def create_invite(
    body: InviteCreateRequest,
    x_superadmin_key: Optional[str] = Header(None),
):
    """
    Protected endpoint — only the platform owner can call this.
    Returns a signed invite token to share with the new enterprise customer.
    Requires header:  X-Superadmin-Key: <SUPERADMIN_KEY env var>
    """
    if not _SUPERADMIN_KEY:
        raise HTTPException(status_code=500, detail={"error": 1, "message": "SUPERADMIN_KEY env var not configured."})
    if x_superadmin_key != _SUPERADMIN_KEY:
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Forbidden."})

    ttl_secs  = body.ttl_days * 86400
    token     = _make_invite_token(body.email, ttl_secs=ttl_secs)
    expiry_ts = int(time.time()) + ttl_secs
    return {
        "error":      0,
        "email":      body.email,
        "token":      token,
        "expires_at": expiry_ts,
        "expires_in": f"{body.ttl_days} days",
        "usage":      f"Pass this token as invite_token in POST /api/admin/onboard",
    }


def _get_user_role_info(user_id: str) -> dict:
    """
    After login, returns the user's plan, org_id, and role.
    - plan: "free" | "enterprise" | etc.
    - is_enterprise_admin: True only if plan=enterprise AND role in (admin, owner)
    - role: "owner" | "admin" | "member" | None
    - org_id: UUID string | None
    """
    result = {
        "plan": "free",
        "is_enterprise_admin": False,
        "role": None,
        "org_id": None,
    }

    # Step 1: get plan
    sub_res = (
        supabase_service
        .table("user_subscriptions")
        .select("plan_id, status")
        .eq("user_id", user_id)
        .execute()
    )
    if not sub_res.data:
        return result

    sub = sub_res.data[0]
    result["plan"] = sub.get("plan_id", "free")

    # Step 2: only enterprise active users get admin check
    if sub.get("plan_id") != "enterprise" or sub.get("status") != "active":
        return result

    # Step 3: check organization membership and role
    org_res = (
        supabase_service
        .table("organization_members")
        .select("org_id, role")
        .eq("user_id", user_id)
        .execute()
    )
    if not org_res.data:
        return result

    membership = org_res.data[0]
    result["org_id"] = membership.get("org_id")
    result["role"] = membership.get("role")
    result["is_enterprise_admin"] = membership.get("role") in ("admin", "owner")

    return result

# ── Personal email domains blocked for enterprise signup ──────────────────────
_PERSONAL_DOMAINS = {
    "gmail.com","googlemail.com","yahoo.com","yahoo.in","yahoo.co.in","yahoo.co.uk",
    "yahoo.com.au","ymail.com","outlook.com","hotmail.com","hotmail.in","hotmail.co.uk",
    "live.com","live.in","msn.com","aol.com","icloud.com","me.com","mac.com",
    "protonmail.com","proton.me","gmx.com","gmx.net","mail.com","yandex.com",
    "yandex.ru","rediffmail.com","inbox.com","rocketmail.com","aim.com",
}

def _is_personal_email(email: str) -> bool:
    domain = email.lower().split("@")[-1] if "@" in email else ""
    return domain in _PERSONAL_DOMAINS


# ── GET /api/plans ────────────────────────────────────────────────────────────
@router.get("/plans")
def get_plans():
    """Returns all available plans for the signup page."""
    try:
        res = supabase_service.table("plans").select("id, name, price_monthly").order("price_monthly").execute()
        return {"error": 0, "plans": res.data or []}
    except Exception:
        return {"error": 0, "plans": [
            {"id": "free",       "name": "Free",       "price_monthly": 0},
            {"id": "pro",        "name": "Pro",         "price_monthly": 2999},
            {"id": "enterprise", "name": "Enterprise",  "price_monthly": None},
        ]}


# ── GET /api/plan-pricing ─────────────────────────────────────────────────────
@router.get("/plan-pricing")
def get_plan_pricing(plan_id: Optional[str] = None):
    """
    Returns billing period options (monthly / quarterly / annual) for a plan.
    ?plan_id=pro  →  pricing rows for Pro only
    No param      →  all active pricing rows
    """
    try:
        q = supabase_service.table("plan_pricing") \
            .select("plan_id, billing_period, price_per_month, total_price, discount_pct, badge, savings_label, sort_order") \
            .eq("is_active", True) \
            .order("sort_order")
        if plan_id:
            q = q.eq("plan_id", plan_id.lower().strip())
        res = q.execute()
        if res.data:
            return {"error": 0, "pricing": res.data}
    except Exception as e:
        print(f"[plan-pricing] DB error: {e}")

    # Fallback hardcoded pricing (INR) if table not yet created
    fallback = {
        "pro": [
            {"plan_id":"pro","billing_period":"annual",   "price_per_month":1999,"total_price":23988,"discount_pct":33,"badge":"Most popular","savings_label":"33% savings","sort_order":1},
            {"plan_id":"pro","billing_period":"quarterly","price_per_month":2699,"total_price":8097, "discount_pct":10,"badge":"",            "savings_label":"10% savings","sort_order":2},
            {"plan_id":"pro","billing_period":"monthly",  "price_per_month":2999,"total_price":2999, "discount_pct":0, "badge":"",            "savings_label":"",           "sort_order":3},
        ],
        "free": [
            {"plan_id":"free","billing_period":"monthly","price_per_month":0,"total_price":0,"discount_pct":0,"badge":"","savings_label":"","sort_order":1},
        ],
    }
    if plan_id and plan_id.lower() in fallback:
        return {"error": 0, "pricing": fallback[plan_id.lower()]}
    all_rows = [row for rows in fallback.values() for row in rows]
    return {"error": 0, "pricing": all_rows}


# ── GET /api/plan-settings ────────────────────────────────────────────────────
@router.get("/plan-settings")
def get_plan_settings(plan: Optional[str] = None):
    """
    Returns features available for a plan from the plan_settings table.
    ?plan=free        → features for free plan only
    ?plan=pro         → features for pro plan only
    ?plan=enterprise  → features for enterprise plan only
    No param          → all plans grouped by plan_name
    """
    try:
        q = supabase_service \
            .table("plan_settings") \
            .select("plan_name, feature, description")

        if plan:
            q = q.eq("plan_name", plan.lower().strip())

        res = q.order("plan_name").execute()

        if not res.data:
            return {"error": 0, "plan_settings": {}}

        # Group features by plan_name
        grouped: dict = {}
        for row in res.data:
            pname = row["plan_name"]
            if pname not in grouped:
                grouped[pname] = []
            grouped[pname].append({
                "feature":     row["feature"],
                "description": row.get("description", ""),
            })

        # If a specific plan was requested return flat list, else return all grouped
        if plan:
            plan_key = plan.lower().strip()
            return {
                "error":    0,
                "plan":     plan_key,
                "features": grouped.get(plan_key, []),
                "count":    len(grouped.get(plan_key, [])),
            }

        return {
            "error":         0,
            "plan_settings": grouped,
        }

    except Exception as e:
        return {"error": 1, "message": f"Failed to fetch plan settings: {str(e)}"}


class AuthRequest(BaseModel):
    email: str
    password: str
    browser_id: str
    ext_id: Optional[str] = None   # Chrome extension ID — present only when called from extension

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


class SignupRequest(BaseModel):
    email: str
    password: str
    browser_id: str
    plan_id: Optional[str] = "free"       # "free" | "pro" | "enterprise"
    full_name: Optional[str] = None       # required for enterprise
    company_name: Optional[str] = None    # required for enterprise
    ext_id: Optional[str] = None          # Chrome extension ID — present only when called from extension

@router.post("/signup")
def signup(data: SignupRequest):
    plan_id = (data.plan_id or "free").lower().strip()

    # ── Enterprise: reject personal email domains ─────────────────────────────
    if plan_id == "enterprise":
        if not data.full_name or not data.full_name.strip():
            raise HTTPException(status_code=400, detail={"error": 1, "message": "Full name is required for enterprise signup."})
        if not data.company_name or not data.company_name.strip():
            raise HTTPException(status_code=400, detail={"error": 1, "message": "Company name is required for enterprise signup."})
        if _is_personal_email(data.email):
            raise HTTPException(status_code=400, detail={
                "error": 1,
                "message": "Enterprise plan requires a business email address. Personal email providers (Gmail, Yahoo, Outlook, etc.) are not allowed.",
            })

    # ── Create Supabase auth user ─────────────────────────────────────────────
    try:
        res = supabase.auth.sign_up({"email": data.email, "password": data.password})
    except Exception as e:
        msg = str(e).lower()
        if "already registered" in msg or "user already exists" in msg:
            raise HTTPException(status_code=409, detail={"error": 1, "message": "An account with this email already exists."})
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Signup failed. Please try again."})

    if res.user is None:
        raise HTTPException(status_code=409, detail={"error": 1, "message": "An account with this email already exists."})

    user_id = str(res.user.id)

    # ── Register browser / extension ─────────────────────────────────────────
    try:
        device_row: dict = {"user_id": user_id, "browser_id": data.browser_id}
        if data.ext_id:
            device_row["ext_id"] = data.ext_id   # links this device to a Chrome extension
        supabase.table("user_devices").insert(device_row).execute()
    except Exception:
        pass

    # ── Create subscription ───────────────────────────────────────────────────
    # Always create a fresh service client here so we never rely on a
    # module-level client that may have been built before env vars loaded.
    _svc_key = os.getenv("SUPABASE_SERVICE_KEY", "") or _SERVICE_KEY
    _svc = create_client(SUPABASE_URL, _svc_key) if _svc_key else supabase_service

    sub_plan_id   = plan_id    # "free" | "pro" | "enterprise"
    sub_status    = "inactive" # new signups start inactive until payment is confirmed
    _sub_err: Optional[str] = None
    _sub_row = {"user_id": user_id, "plan_id": sub_plan_id, "status": sub_status}

    # supabase-py may return errors in result.data instead of raising exceptions,
    # so we check result.data explicitly after every insert/update.
    _sub_inserted = False
    try:
        _r = _svc.table("user_subscriptions").insert(_sub_row).execute()
        if _r.data:
            _sub_inserted = True
            print(f"[signup] user_subscriptions inserted for {user_id}: {_r.data}")
        else:
            _sub_err = f"insert returned no data (silent failure): {_r}"
            print(f"[signup] user_subscriptions insert silent fail: {_r}")
    except Exception as _e1:
        _sub_err = str(_e1)
        print(f"[signup] user_subscriptions insert exception: {_e1}")

    if not _sub_inserted:
        # Row may already exist — try UPDATE
        try:
            _r2 = _svc.table("user_subscriptions").update(
                {"plan_id": sub_plan_id, "status": sub_status}
            ).eq("user_id", user_id).execute()
            if _r2.data:
                _sub_err = None
                _sub_inserted = True
                print(f"[signup] user_subscriptions updated for {user_id}: {_r2.data}")
            else:
                # No existing row AND insert failed — force insert via service REST
                print(f"[signup] update also returned no data, trying raw insert")
                _r3 = supabase_service.table("user_subscriptions").insert(_sub_row).execute()
                if _r3.data:
                    _sub_err = None
                    print(f"[signup] user_subscriptions raw insert succeeded: {_r3.data}")
                else:
                    _sub_err = f"all attempts failed. insert: {_sub_err} | update: {_r2}"
                    print(f"[signup] ALL user_subscriptions attempts failed")
        except Exception as _e2:
            _sub_err = f"update exception: {_e2}"
            print(f"[signup] user_subscriptions update exception: {_e2}")

    # ── Default settings row — all features False (inactive until payment) ──────
    from app.core.plan_features import build_settings_row
    _settings_row = build_settings_row(user_id, sub_plan_id, _svc)
    _set_err: Optional[str] = None
    _set_inserted = False
    try:
        _s = _svc.table("user_settings").insert(_settings_row).execute()
        if _s.data:
            _set_inserted = True
            print(f"[signup] user_settings inserted for {user_id}")
        else:
            _set_err = f"insert returned no data: {_s}"
            print(f"[signup] user_settings insert silent fail: {_s}")
    except Exception as _e3:
        _set_err = str(_e3)
        print(f"[signup] user_settings insert exception: {_e3}")

    if not _set_inserted:
        try:
            _upd = {k: v for k, v in _settings_row.items() if k != "user_id"}
            _s2 = _svc.table("user_settings").update(_upd).eq("user_id", user_id).execute()
            if _s2.data:
                _set_err = None
                print(f"[signup] user_settings updated for {user_id}")
            else:
                _set_err = f"update also returned no data: {_s2}"
                print(f"[signup] user_settings update silent fail: {_s2}")
        except Exception as _e4:
            _set_err = f"update exception: {_e4}"
            print(f"[signup] user_settings update exception: {_e4}")

    # ── Enterprise: create org + assign owner ─────────────────────────────────
    org_id = None
    if plan_id == "enterprise":
        try:
            company  = (data.company_name or "").strip()
            org_id   = str(uuid.uuid4())
            supabase_service.table("organizations").insert({
                "id":            org_id,
                "name":          company,
                "billing_email": data.email,
                "created_by":    user_id,
            }).execute()
            supabase_service.table("organization_members").insert({
                "org_id":     org_id,
                "user_id":    user_id,
                "role":       "owner",
                "invited_by": user_id,
            }).execute()
        except Exception:
            pass

    from_extension = bool(data.ext_id)

    # ── Send welcome email with login credentials ─────────────────────────────
    _send_welcome_email(
        email     = data.email,
        password  = data.password,
        full_name = data.full_name or "",
    )

    if res.session is None:
        return {
            "success":        True,
            "plan_id":        sub_plan_id,
            "plan_status":    sub_status,
            "org_id":         org_id,
            "from_extension": from_extension,
            "message":        "Signup successful. Please verify your email.",
        }

    return {
        "success":        True,
        "access_token":   res.session.access_token,
        "refresh_token":  res.session.refresh_token,
        "plan_id":        sub_plan_id,
        "plan_status":    sub_status,
        "org_id":         org_id,
        "from_extension": from_extension,
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

    # 3️⃣ If browser/extension not registered → register it
    if not device.data:
        device_row: dict = {"user_id": user_id, "browser_id": data.browser_id}
        if data.ext_id:
            device_row["ext_id"] = data.ext_id
        supabase.table("user_devices").insert(device_row).execute()

    # 4️⃣ Fetch plan so the frontend can redirect to the right dashboard
    plan_id     = "free"
    plan_status = "inactive"
    try:
        sub = supabase_service.table("user_subscriptions").select("plan_id, status").eq("user_id", str(user_id)).execute()
        if sub.data:
            plan_id     = sub.data[0].get("plan_id", "free")
            plan_status = sub.data[0].get("status",  "inactive")
    except Exception:
        pass

    # 5️⃣ Successful login response
    return {
        "success":        True,
        "access_token":   res.session.access_token,
        "refresh_token":  res.session.refresh_token,
        "plan_id":        plan_id,
        "plan_status":    plan_status,
        "from_extension": bool(data.ext_id),
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
@router.post("/admin/login")
def admin_login(data: AuthRequest):
    # 1️⃣ Authenticate with Supabase
    try:
        res = supabase.auth.sign_in_with_password({
            "email": data.email,
            "password": data.password,
        })
    except Exception:
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid email or password"})

    if not res or not res.user or not res.session:
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid email or password"})

    user_id = str(res.user.id)

    # 2️⃣ Must have an active enterprise subscription
    sub_res = (
        supabase_service
        .table("user_subscriptions")
        .select("plan_id, status")
        .eq("user_id", user_id)
        .execute()
    )
    if not sub_res.data:
        raise HTTPException(status_code=403, detail={"error": 1, "message": "No subscription found. Contact your administrator."})

    sub     = sub_res.data[0]
    plan_id = sub.get("plan_id", "free")
    status  = sub.get("status",  "inactive")

    if plan_id != "enterprise":
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Access denied. Enterprise plan required."})

    if status != "active":
        raise HTTPException(status_code=403, detail={
            "error":       1,
            "plan_status": "pending",
            "message":     "Your enterprise plan is pending activation. Contact your SecureLint account manager.",
        })

    # 3️⃣ Must be admin or owner in an organisation
    org_res = (
        supabase_service
        .table("organization_members")
        .select("org_id, role")
        .eq("user_id", user_id)
        .execute()
    )
    if not org_res.data:
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Access denied. You are not part of any organisation."})

    membership = org_res.data[0]
    role       = membership.get("role")
    if role not in ("admin", "owner"):
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Access denied. Admin or owner role required."})

    # 4️⃣ All checks passed
    return {
        "error":        0,
        "success":      True,
        "access_token": res.session.access_token,
        "refresh_token":res.session.refresh_token,
        "role":         role,
        "org_id":       membership.get("org_id"),
        "plan_status":  "active",
    }







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


# ── Google OAuth Sign-In / Sign-Up ───────────────────────────────────────────

class GoogleSignInRequest(BaseModel):
    id_token: str
    browser_id: str
    ext_id: Optional[str] = None


def _derive_google_password(google_sub: str) -> str:
    """
    Deterministically derive a server-side password from the Google user's `sub` claim.
    This password is never exposed to the user — they only authenticate via Google.
    CSRF-safe: requires knowing GOOGLE_CLIENT_SECRET on the server.
    """
    secret = _GOOGLE_CLIENT_SECRET or _GOOGLE_CLIENT_ID
    raw = f"{google_sub}:{secret}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"Goog@{digest[:30]}"


@router.post("/google-signin")
def google_signin(data: GoogleSignInRequest):
    """
    Google Sign-In / Sign-Up via id_token.

    CSRF security:
    - The id_token is cryptographically signed by Google's private key.
    - We verify:
        * Signature (via Google's public certs)
        * aud == our client_id  (prevents cross-app token injection)
        * iss == accounts.google.com
        * exp  (token not expired)
    - The popup-based GSI flow never involves a redirect or state parameter,
      so redirect-based CSRF attacks are impossible.
    """
    if not _GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail={"error": 1, "message": "Google OAuth not configured on server."})

    # ── Step 1: verify the id_token with Google ───────────────────────────────
    try:
        from google.oauth2 import id_token as google_id_token
        from google.auth.transport import requests as google_requests

        idinfo = google_id_token.verify_oauth2_token(
            data.id_token,
            google_requests.Request(),
            _GOOGLE_CLIENT_ID,
        )
    except ValueError as e:
        # Covers: expired token, wrong aud, bad signature — all CSRF/replay attacks
        print(f"[google-signin] id_token verification failed: {e}")
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid or expired Google token."})
    except Exception as e:
        print(f"[google-signin] unexpected verification error: {e}")
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Google token verification failed."})

    google_sub   = idinfo["sub"]          # unique stable Google user ID
    email        = idinfo.get("email", "")
    full_name    = idinfo.get("name", "") or idinfo.get("given_name", "")
    avatar_url   = idinfo.get("picture", "")
    email_verified = idinfo.get("email_verified", False)

    if not email:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Google account has no email address."})
    if not email_verified:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Google account email is not verified."})

    print(f"[google-signin] verified token for {email} (sub={google_sub[:8]}…)")

    # ── Step 2: derive a deterministic password (never shown to user) ─────────
    derived_pw = _derive_google_password(google_sub)

    # ── Step 3: try signing in first (existing user) ──────────────────────────
    session_res = None
    is_new_user = False

    try:
        sign_in = supabase.auth.sign_in_with_password({"email": email, "password": derived_pw})
        if sign_in and sign_in.session:
            session_res = sign_in.session
            print(f"[google-signin] existing user signed in: {email}")
    except Exception:
        pass  # User doesn't exist yet — we'll create them below

    # ── Step 4: create new user if sign-in failed ─────────────────────────────
    if session_res is None:
        _svc_key = os.getenv("SUPABASE_SERVICE_KEY", "") or _SERVICE_KEY
        _svc = create_client(SUPABASE_URL, _svc_key) if _svc_key else supabase_service

        try:
            create_res = _svc.auth.admin.create_user({
                "email":          email,
                "password":       derived_pw,
                "email_confirm":  True,
                "user_metadata":  {
                    "full_name":   full_name,
                    "avatar_url":  avatar_url,
                    "provider":    "google",
                    "google_sub":  google_sub,
                },
            })
        except Exception as e:
            msg = str(e).lower()
            # User may already exist (race) — try sign-in once more
            if "already" in msg or "exists" in msg or "duplicate" in msg:
                try:
                    retry = supabase.auth.sign_in_with_password({"email": email, "password": derived_pw})
                    if retry and retry.session:
                        session_res = retry.session
                except Exception:
                    pass
            if session_res is None:
                print(f"[google-signin] admin.create_user failed for {email}: {e}")
                raise HTTPException(status_code=500, detail={"error": 1, "message": "Failed to create account. Please try again."})

        if session_res is None:
            # Sign in the freshly created user
            try:
                sign_in2 = supabase.auth.sign_in_with_password({"email": email, "password": derived_pw})
                if sign_in2 and sign_in2.session:
                    session_res = sign_in2.session
                    is_new_user = True
            except Exception as e2:
                print(f"[google-signin] sign_in after create failed for {email}: {e2}")
                raise HTTPException(status_code=500, detail={"error": 1, "message": "Account created but sign-in failed. Try again."})

    if not session_res:
        raise HTTPException(status_code=500, detail={"error": 1, "message": "Authentication failed. Please try again."})

    user_id = str(session_res.user.id)

    # ── Step 5: bootstrap subscription + settings for new users ──────────────
    if is_new_user:
        _svc_key = os.getenv("SUPABASE_SERVICE_KEY", "") or _SERVICE_KEY
        _svc = create_client(SUPABASE_URL, _svc_key) if _svc_key else supabase_service

        # Subscription — start as inactive (free) until payment
        try:
            _svc.table("user_subscriptions").insert({
                "user_id": user_id, "plan_id": "free", "status": "inactive",
            }).execute()
        except Exception:
            pass

        # Default settings — all features False until payment confirmed
        try:
            from app.core.plan_features import build_settings_row
            _svc.table("user_settings").insert(
                build_settings_row(user_id, "free", _svc)
            ).execute()
        except Exception:
            pass

        # Register browser/device
        try:
            device_row: dict = {"user_id": user_id, "browser_id": data.browser_id}
            if data.ext_id:
                device_row["ext_id"] = data.ext_id
            supabase.table("user_devices").insert(device_row).execute()
        except Exception:
            pass

        # Send welcome email (best-effort)
        _send_welcome_email(email=email, password="(Google Sign-In — no password)", full_name=full_name)
        print(f"[google-signin] new user created: {email} (user_id={user_id})")

    # ── Step 6: get plan info ─────────────────────────────────────────────────
    plan_id = "free"
    plan_status = "inactive"
    try:
        sub = supabase_service.table("user_subscriptions").select("plan_id, status").eq("user_id", user_id).execute()
        if sub.data:
            plan_id     = sub.data[0].get("plan_id",  "free")
            plan_status = sub.data[0].get("status",   "inactive")
    except Exception:
        pass

    return {
        "success":        True,
        "access_token":   session_res.access_token,
        "refresh_token":  session_res.refresh_token,
        "plan_id":        plan_id,
        "plan_status":    plan_status,
        "is_new_user":    is_new_user,
        "from_extension": bool(data.ext_id),
    }