"""
Coupon API
──────────
POST /api/coupons/validate  — validate a coupon code and preview the discount
"""

from fastapi import APIRouter, HTTPException, Header, Request
from pydantic import BaseModel
from supabase import create_client
from typing import Optional
from datetime import datetime, timezone
import os, time, threading

from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

_svc = (
    create_client(SUPABASE_URL, _SERVICE_KEY)
    if _SERVICE_KEY
    else create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
)


# ── In-memory rate limiter (brute-force guard) ────────────────────────────────
# Allows MAX_ATTEMPTS per user per WINDOW_SECS on /coupons/validate.
# Serverless-safe: resets on cold start, but still stops automated scripts
# running within a single function instance.

_rl_lock      = threading.Lock()
_rl_buckets: dict[str, list[float]] = {}   # user_id → [timestamp, …]
_RL_MAX       = 15      # max attempts
_RL_WINDOW    = 60      # per 60 seconds
_RL_BLOCK     = 300     # block for 5 min after burst

def _rate_limit_check(user_id: str) -> None:
    """Raise 429 if the user has exceeded the validate rate limit."""
    now = time.monotonic()
    with _rl_lock:
        hits = _rl_buckets.get(user_id, [])
        # Drop timestamps outside the window
        hits = [t for t in hits if now - t < _RL_WINDOW]
        if len(hits) >= _RL_MAX:
            raise HTTPException(
                status_code=429,
                detail={"error": 1, "message": "Too many coupon attempts. Please wait a few minutes."},
            )
        hits.append(now)
        _rl_buckets[user_id] = hits


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


def _compute_discount(coupon: dict, original_paise: int) -> int:
    """Return discount amount in paise (never exceeds original_paise)."""
    if coupon["discount_type"] == "percent":
        discount = int(original_paise * float(coupon["discount_value"]) / 100)
        if coupon.get("max_discount"):
            discount = min(discount, int(float(coupon["max_discount"]) * 100))
    else:  # flat
        discount = int(float(coupon["discount_value"]) * 100)
    return min(discount, original_paise)


def _validate_coupon_row(coupon: dict, user_id: str,
                         plan_id: Optional[str],
                         billing_period: Optional[str],
                         original_paise: int) -> str | None:
    """
    Lightweight pre-flight checks (non-atomic, for fast feedback).
    The real atomic enforcement happens inside the claim_coupon() RPC.
    Returns an error string if clearly invalid, None if probably valid.
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

    return None


# ── POST /api/coupons/validate ────────────────────────────────────────────────

class ValidateCouponRequest(BaseModel):
    code:                str
    plan_id:             Optional[str]   = None
    billing_period:      Optional[str]   = None
    original_amount_inr: Optional[float] = None


@router.post("/coupons/validate")
def validate_coupon(body: ValidateCouponRequest, authorization: Optional[str] = Header(None)):
    """
    Validates a coupon / promo code.
    Returns discount info and the final price (preview only — nothing committed).
    Rate-limited to 15 attempts per user per 60 seconds.
    """
    user_id, _ = _require_user(authorization)

    # Brute-force guard
    _rate_limit_check(user_id)

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

    err = _validate_coupon_row(coupon, user_id, body.plan_id, body.billing_period, original_paise)
    if err:
        raise HTTPException(status_code=400, detail={"error": 1, "message": err})

    discount_paise = _compute_discount(coupon, original_paise) if original_paise > 0 else 0
    final_paise    = original_paise - discount_paise

    return {
        "error":          0,
        "valid":          True,
        "coupon_id":      coupon["id"],
        "code":           coupon["code"],
        "description":    coupon.get("description"),
        "discount_type":  coupon["discount_type"],
        "discount_value": float(coupon["discount_value"]),
        "original_inr":   round(original_paise / 100),
        "discount_inr":   round(discount_paise / 100),
        "final_inr":      round(final_paise / 100),
    }
