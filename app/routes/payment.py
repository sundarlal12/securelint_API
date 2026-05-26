from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from supabase import create_client
from typing import Optional
import os, hmac, hashlib, razorpay
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
_RZP_KEY_ID  = os.getenv("RAZORPAY_KEY_ID", "")
_RZP_SECRET  = os.getenv("RAZORPAY_KEY_SECRET", "")

supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


def _rzp_client():
    if not _RZP_KEY_ID or not _RZP_SECRET:
        raise HTTPException(status_code=500, detail={"error": 1, "message": "Razorpay keys not configured."})
    return razorpay.Client(auth=(_RZP_KEY_ID, _RZP_SECRET))


def _require_user(token: Optional[str]) -> str:
    """Validate Bearer token and return user_id."""
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Authentication required."})
    jwt = token[7:]
    try:
        supabase_anon = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        user = supabase_anon.auth.get_user(jwt)
        return str(user.user.id)
    except Exception:
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid or expired token."})


# ── GET /api/payment/key ───────────────────────────────────────────────────────
@router.get("/payment/key")
def get_rzp_key():
    """Returns the Razorpay key ID for the frontend."""
    if not _RZP_KEY_ID:
        raise HTTPException(status_code=500, detail={"error": 1, "message": "Razorpay not configured."})
    return {"error": 0, "key_id": _RZP_KEY_ID}


# ── POST /api/payment/create-order ────────────────────────────────────────────
class CreateOrderRequest(BaseModel):
    plan_id:        str            # "free" | "pro"
    billing_period: Optional[str] = "monthly"   # "monthly" | "quarterly" | "annual"

@router.post("/payment/create-order")
def create_order(
    body: CreateOrderRequest,
    authorization: Optional[str] = Header(None),
):
    user_id        = _require_user(authorization)
    billing_period = (body.billing_period or "monthly").lower().strip()

    # 1️⃣ Look up total price from plan_pricing table
    price_inr = None
    plan_name = body.plan_id.capitalize()
    try:
        pp_res = supabase_service.table("plan_pricing") \
            .select("total_price") \
            .eq("plan_id", body.plan_id) \
            .eq("billing_period", billing_period) \
            .eq("is_active", True) \
            .execute()
        if pp_res.data:
            price_inr = float(pp_res.data[0]["total_price"])
    except Exception:
        pass

    # 2️⃣ Fall back to plans.price_monthly × months if plan_pricing not set up
    if price_inr is None:
        months_map = {"monthly": 1, "quarterly": 3, "annual": 12}
        months = months_map.get(billing_period, 1)
        plan_res = supabase_service.table("plans").select("id, name, price_monthly").eq("id", body.plan_id).execute()
        if plan_res.data:
            plan      = plan_res.data[0]
            price_inr = float(plan.get("price_monthly") or 0) * months
            plan_name = plan.get("name", body.plan_id)
        else:
            fallback  = {"free": 0, "pro": 2999}
            price_inr = fallback.get(body.plan_id, 0) * months

    price_paise = int(price_inr * 100)

    if price_paise == 0:
        # Free plan — activate directly, no payment needed
        try:
            supabase_service.table("user_subscriptions").upsert(
                {"user_id": user_id, "plan_id": body.plan_id, "status": "active"},
                on_conflict="user_id",
            ).execute()
        except Exception:
            pass
        return {"error": 0, "free": True, "plan_id": body.plan_id, "message": "Free plan activated."}

    client = _rzp_client()
    try:
        order = client.order.create({
            "amount":   price_paise,
            "currency": "INR",
            "notes":    {"user_id": user_id, "plan_id": body.plan_id, "billing_period": billing_period},
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Failed to create order: {e}"})

    return {
        "error":          0,
        "order_id":       order["id"],
        "amount":         order["amount"],
        "currency":       order["currency"],
        "plan_id":        body.plan_id,
        "plan_name":      plan_name,
        "billing_period": billing_period,
        "key_id":         _RZP_KEY_ID,
    }


# ── POST /api/payment/verify ─────────────────────────────────────────────────
class VerifyPaymentRequest(BaseModel):
    razorpay_order_id:   str
    razorpay_payment_id: str
    razorpay_signature:  str
    plan_id:             str
    billing_period:      Optional[str] = "monthly"

@router.post("/payment/verify")
def verify_payment(
    body: VerifyPaymentRequest,
    authorization: Optional[str] = Header(None),
):
    user_id = _require_user(authorization)

    # Verify HMAC signature
    expected = hmac.new(
        _RZP_SECRET.encode(),
        f"{body.razorpay_order_id}|{body.razorpay_payment_id}".encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, body.razorpay_signature):
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Payment verification failed. Invalid signature."})

    # Activate subscription
    billing_period = (body.billing_period or "monthly").lower().strip()
    try:
        supabase_service.table("user_subscriptions").upsert(
            {"user_id": user_id, "plan_id": body.plan_id, "status": "active", "billing_period": billing_period},
            on_conflict="user_id",
        ).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Payment verified but subscription update failed: {e}"})

    return {
        "error":          0,
        "success":        True,
        "plan_id":        body.plan_id,
        "billing_period": billing_period,
        "plan_status":    "active",
        "message":        f"Payment successful. {body.plan_id.capitalize()} plan activated.",
    }
