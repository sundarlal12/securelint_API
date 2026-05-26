

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from supabase import create_client
from typing import Optional
import os, uuid, hmac, hashlib, base64, time
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

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

    # ── Default settings row — enabled fields depend on plan tier ────────────
    _is_pro        = sub_plan_id in ("pro",)
    _is_enterprise = sub_plan_id in ("enterprise",)
    _is_paid       = _is_pro or _is_enterprise

    _settings_row = {
        "user_id":  user_id,
        "Plans":    sub_plan_id,

        # ── Free + Pro + Enterprise ───────────────────────────────────────────
        "enable_detection":    True,
        "detect_medium":       True,
        "detect_low":          True,
        "show_notifications":  True,
        "auto_mask_inputs":    True,
        "auto_mask_textareas": True,
        "overlay_input":       True,
        "overlay_textarea":    True,
        "show_risk_score":     True,
        "show_recent_activity":True,
        "masking_style":       "blur",

        # ── Pro + Enterprise only ─────────────────────────────────────────────
        "auto_mask_critical":   _is_paid,
        "auto_mask_editor":     _is_paid,
        "mask_console":         _is_paid,
        "overlay_editor":       _is_paid,
        "scan_large_docs":      _is_paid,
        "detect_critical":      _is_paid,
        "detect_high":          _is_paid,
        "notify_critical":      _is_paid,
        "notify_high":          _is_paid,
        "realtime_updates":     _is_paid,
        "animated_charts":      _is_paid,
        "auto_refresh":         _is_paid,
        "preserve_context":     _is_paid,
        "site_exclusions_status": _is_paid,
        "global_masking_status":  _is_paid,
        "block_network_secrets":  _is_paid,
        "block_form_submission":  _is_paid,
        "site_exclusions":        None,

        # ── Enterprise only ───────────────────────────────────────────────────
        "aggressive_email_blocking": _is_enterprise,
        "email_dlp_enabled":         _is_enterprise,
        "enterprise_data_collection":_is_enterprise,
        "waf_social_domain":         _is_enterprise,
        "enterprise_email_domains":  None,
    }
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