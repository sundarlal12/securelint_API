"""
Coupon & Referral API
─────────────────────
GET  /api/coupons/my-referral-code       — get (or auto-create) the caller's referral code
POST /api/coupons/validate               — validate a coupon code and preview the discount
POST /api/coupons/referral-signup        — register that a referee signed up via a referral code
POST /api/coupons/reward-referrer        — called internally after a referred user pays
"""

from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from supabase import create_client
from typing import Optional
from datetime import datetime, timezone
import os, random, string

from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
_BASE_URL    = os.getenv("BASE_URL", "https://securelint.in")

_svc = (
    create_client(SUPABASE_URL, _SERVICE_KEY)
    if _SERVICE_KEY
    else create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _require_user(token: Optional[str]):
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Authentication required."})
    jwt_token = token[7:]
    try:
        anon = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        u = anon.auth.get_user(jwt_token)
        return str(u.user.id), (u.user.email or "")
    except Exception:
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid or expired token."})


def _gen_code(prefix: str = "REF", length: int = 8) -> str:
    """Generate a unique-looking referral code like REF-AB3X9K2M."""
    chars = string.ascii_uppercase + string.digits
    return f"{prefix}-" + "".join(random.choices(chars, k=length))


def _compute_discount(coupon: dict, original_paise: int) -> int:
    """Return discount amount in paise (never exceeds original_paise)."""
    if coupon["discount_type"] == "percent":
        discount = int(original_paise * float(coupon["discount_value"]) / 100)
        if coupon.get("max_discount"):
            discount = min(discount, int(float(coupon["max_discount"]) * 100))
    else:  # flat
        discount = int(float(coupon["discount_value"]) * 100)

    return min(discount, original_paise)  # can't discount more than the price


def _validate_coupon_row(coupon: dict, user_id: str,
                         plan_id: Optional[str],
                         billing_period: Optional[str],
                         original_paise: int) -> str | None:
    """
    Validate a coupon row against the current purchase context.
    Returns an error string if invalid, or None if valid.
    """
    now = datetime.now(timezone.utc)

    if not coupon.get("is_active"):
        return "Coupon is no longer active."

    valid_from = coupon.get("valid_from")
    if valid_from and datetime.fromisoformat(str(valid_from).replace("Z", "+00:00")) > now:
        return "Coupon is not valid yet."

    valid_until = coupon.get("valid_until")
    if valid_until and datetime.fromisoformat(str(valid_until).replace("Z", "+00:00")) < now:
        return "Coupon has expired."

    max_uses = coupon.get("max_uses")
    if max_uses is not None and int(coupon.get("current_uses", 0)) >= int(max_uses):
        return "Coupon usage limit has been reached."

    min_order = int(float(coupon.get("min_order_amount") or 0) * 100)
    if original_paise < min_order:
        return f"Minimum order amount for this coupon is ₹{min_order // 100}."

    applicable_plans = coupon.get("applicable_plans")
    if applicable_plans and plan_id and plan_id not in applicable_plans:
        return f"Coupon is not valid for the '{plan_id}' plan."

    applicable_periods = coupon.get("applicable_periods")
    if applicable_periods and billing_period and billing_period not in applicable_periods:
        return f"Coupon is not valid for '{billing_period}' billing."

    # Check per-user usage limit
    uses_per_user = int(coupon.get("uses_per_user") or 1)
    try:
        used_res = (
            _svc.table("coupon_redemptions")
            .select("id", count="exact")
            .eq("coupon_id", coupon["id"])
            .eq("user_id", user_id)
            .not_.is_("payment_transaction_id", "null")
            .execute()
        )
        if (used_res.count or 0) >= uses_per_user:
            return "You have already used this coupon."
    except Exception:
        pass  # fail-open on DB error

    return None  # all checks passed


# ── GET /api/coupons/my-referral-code ─────────────────────────────────────────

@router.get("/coupons/my-referral-code")
def my_referral_code(authorization: Optional[str] = Header(None)):
    """
    Returns the caller's personal referral code (and referral link).
    Auto-creates one if it doesn't exist yet.
    """
    user_id, _ = _require_user(authorization)

    # Check if user already has a referral coupon
    try:
        res = (
            _svc.table("coupons")
            .select("code, current_uses, id")
            .eq("owner_user_id", user_id)
            .eq("source", "referral")
            .limit(1)
            .execute()
        )
        if res.data:
            row = res.data[0]
            return {
                "error": 0,
                "referral_code": row["code"],
                "referral_link": f"{_BASE_URL}/signup?ref={row['code']}",
                "uses": row["current_uses"],
                "coupon_id": row["id"],
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"DB error: {e}"})

    # Create a new referral coupon for this user
    attempts = 0
    while attempts < 10:
        code = _gen_code("REF")
        try:
            ins = _svc.table("coupons").insert({
                "code":           code,
                "description":    "Referral discount",
                "discount_type":  "percent",
                "discount_value": 20,           # referees get 20% off
                "source":         "referral",
                "owner_user_id":  user_id,
                "max_uses":       None,          # unlimited
                "uses_per_user":  1,
                "is_active":      True,
            }).execute()
            row = ins.data[0]
            return {
                "error": 0,
                "referral_code": row["code"],
                "referral_link": f"{_BASE_URL}/signup?ref={row['code']}",
                "uses": 0,
                "coupon_id": row["id"],
            }
        except Exception:
            attempts += 1  # code collision — retry

    raise HTTPException(status_code=500, detail={"error": 1, "message": "Could not generate referral code."})


# ── POST /api/coupons/validate ─────────────────────────────────────────────────

class ValidateCouponRequest(BaseModel):
    code:           str
    plan_id:        Optional[str] = None
    billing_period: Optional[str] = None
    original_amount_inr: Optional[float] = None  # if known, returns preview discount


@router.post("/coupons/validate")
def validate_coupon(body: ValidateCouponRequest, authorization: Optional[str] = Header(None)):
    """
    Validates a coupon code.
    Returns discount info and the final price (preview only — nothing is committed).
    """
    user_id, _ = _require_user(authorization)

    code = (body.code or "").strip().upper()
    if not code:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Coupon code is required."})

    try:
        res = _svc.table("coupons").select("*").ilike("code", code).limit(1).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"DB error: {e}"})

    if not res.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Invalid coupon code."})

    coupon = res.data[0]
    original_paise = int((body.original_amount_inr or 0) * 100)

    err = _validate_coupon_row(
        coupon, user_id,
        body.plan_id, body.billing_period,
        original_paise,
    )
    if err:
        raise HTTPException(status_code=400, detail={"error": 1, "message": err})

    discount_paise  = _compute_discount(coupon, original_paise) if original_paise > 0 else 0
    final_paise     = original_paise - discount_paise

    return {
        "error":          0,
        "valid":          True,
        "coupon_id":      coupon["id"],
        "code":           coupon["code"],
        "description":    coupon.get("description"),
        "discount_type":  coupon["discount_type"],
        "discount_value": float(coupon["discount_value"]),
        "original_inr":   original_paise / 100,
        "discount_inr":   discount_paise / 100,
        "final_inr":      final_paise / 100,
    }


# ── POST /api/coupons/referral-signup ─────────────────────────────────────────

class ReferralSignupRequest(BaseModel):
    referral_code: str
    referee_email: Optional[str] = None


@router.post("/coupons/referral-signup")
def referral_signup(body: ReferralSignupRequest, authorization: Optional[str] = Header(None)):
    """
    Call this right after a new user signs up via a referral link.
    Records the referral relationship so the referrer gets rewarded after the referee pays.
    """
    referee_id, referee_email = _require_user(authorization)

    code = (body.referral_code or "").strip().upper()
    if not code:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Referral code is required."})

    # Look up the coupon
    try:
        res = _svc.table("coupons").select("*").ilike("code", code).limit(1).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"DB error: {e}"})

    if not res.data or res.data[0].get("source") != "referral":
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Invalid referral code."})

    coupon      = res.data[0]
    referrer_id = coupon.get("owner_user_id")

    if referrer_id == referee_id:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "You cannot refer yourself."})

    # Upsert referral record (ignore duplicate signups for same code+referee)
    try:
        existing = (
            _svc.table("referrals")
            .select("id, status")
            .eq("referee_id", referee_id)
            .execute()
        )
        if existing.data:
            return {"error": 0, "message": "Referral already recorded.", "already_exists": True}

        _svc.table("referrals").insert({
            "referrer_id":   referrer_id,
            "referee_id":    referee_id,
            "referee_email": body.referee_email or referee_email,
            "referral_code": code,
            "status":        "signed_up",
        }).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Could not record referral: {e}"})

    return {"error": 0, "message": "Referral recorded. Discount will apply at checkout."}


# ── POST /api/coupons/reward-referrer  (internal — called from payment.py) ────

def reward_referrer_after_payment(referee_id: str, plan_id: str) -> None:
    """
    After a referred user's payment is confirmed:
    1. Mark the referral as 'paid'
    2. Issue a 20% reward coupon to the referrer (or activate it if already exists)
    This function is best-effort — never raises.
    """
    try:
        ref_res = (
            _svc.table("referrals")
            .select("*")
            .eq("referee_id", referee_id)
            .eq("status", "signed_up")
            .limit(1)
            .execute()
        )
        if not ref_res.data:
            return

        referral    = ref_res.data[0]
        referrer_id = referral["referrer_id"]

        # Issue a one-time 20% reward coupon to the referrer
        reward_code = _gen_code("RWD")
        ins = _svc.table("coupons").insert({
            "code":           reward_code,
            "description":    f"Referral reward — 20% off your next renewal",
            "discount_type":  "percent",
            "discount_value": 20,
            "source":         "referral",
            "owner_user_id":  referrer_id,
            "max_uses":       1,
            "uses_per_user":  1,
            "is_active":      True,
        }).execute()

        reward_coupon_id = ins.data[0]["id"] if ins.data else None

        # Mark referral as rewarded
        _svc.table("referrals").update({
            "status":           "rewarded",
            "reward_coupon_id": reward_coupon_id,
        }).eq("id", referral["id"]).execute()

    except Exception as e:
        print(f"[referral] reward_referrer_after_payment error: {e}")
