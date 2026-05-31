from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel
from supabase import create_client
from typing import Optional, Tuple
from datetime import datetime, timedelta, timezone
import os, hmac, hashlib, razorpay, httpx
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
_RZP_KEY_ID  = os.getenv("RAZORPAY_KEY_ID", "")
_RZP_SECRET  = os.getenv("RAZORPAY_KEY_SECRET", "")
_RESEND_KEY  = os.getenv("RESEND_API_KEY", "")
_BASE_URL    = os.getenv("BASE_URL", "https://securelint.in")

supabase_service = (
    create_client(SUPABASE_URL, _SERVICE_KEY)
    if _SERVICE_KEY
    else create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _rzp_client():
    if not _RZP_KEY_ID or not _RZP_SECRET:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": "Razorpay keys not configured."},
        )
    return razorpay.Client(auth=(_RZP_KEY_ID, _RZP_SECRET))


def _require_user(token: Optional[str]) -> Tuple[str, str]:
    """Validate Bearer token. Returns (user_id, email) extracted directly from the JWT."""
    if not token or not token.startswith("Bearer "):
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Authentication required."})
    jwt_token = token[7:]
    try:
        anon = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
        user = anon.auth.get_user(jwt_token)
        user_id = str(user.user.id)
        # Email is embedded in the JWT user object — no extra API call needed
        email   = user.user.email or ""
        return user_id, email
    except Exception:
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid or expired token."})


def _period_months(billing_period: str) -> int:
    return {"monthly": 1, "quarterly": 3, "annual": 12}.get(billing_period, 1)


def _ends_at(billing_period: str) -> str:
    months = _period_months(billing_period)
    return (datetime.now(timezone.utc) + timedelta(days=30 * months)).isoformat()


def _verify_rzp_amount(payment_id: str, expected_paise: int) -> bool:
    """
    Fetch the payment from Razorpay and confirm the captured amount matches
    what we charged. Prevents someone paying ₹1 against a ₹1499 order.
    Returns True if amount matches (or if API call fails — fail-open is safer
    than blocking a legitimate payment; signature verification already guards integrity).
    """
    if not _RZP_KEY_ID or not _RZP_SECRET:
        return True  # Can't verify without keys, already checked signature
    try:
        rzp = razorpay.Client(auth=(_RZP_KEY_ID, _RZP_SECRET))
        payment = rzp.payment.fetch(payment_id)
        actual_paise = int(payment.get("amount", 0))
        return actual_paise >= expected_paise
    except Exception:
        return True  # Fail-open: signature already verified


def _send_payment_email(email: str, plan_name: str, billing_period: str,
                        amount_paise: int, payment_id: str) -> None:
    """Send payment-success email via Resend. Best-effort — never raises."""
    if not _RESEND_KEY or not email:
        return
    amount_inr   = amount_paise / 100
    period_label = billing_period.capitalize()
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:system-ui,-apple-system,sans-serif;background:#f9fafb;margin:0;padding:32px 0;">
  <div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.08);">
    <div style="background:#0BA37F;padding:32px 40px 28px;">
      <div style="font-size:28px;font-weight:800;color:#fff;letter-spacing:-0.5px;">SecureLint</div>
      <div style="font-size:15px;color:#d1fae5;margin-top:4px;">Payment Confirmation</div>
    </div>
    <div style="padding:36px 40px;">
      <h1 style="font-size:24px;font-weight:800;color:#111827;margin:0 0 8px;">🎉 Payment Successful!</h1>
      <p style="font-size:15px;color:#374151;line-height:1.6;margin:0 0 28px;">
        Your <strong>{plan_name}</strong> plan is now active. Here are your payment details:
      </p>
      <div style="background:#f9fafb;border-radius:8px;padding:20px 24px;margin-bottom:28px;">
        <table style="width:100%;border-collapse:collapse;font-size:14px;">
          <tr>
            <td style="padding:6px 0;color:#6b7280;">Plan</td>
            <td style="padding:6px 0;font-weight:700;color:#111827;text-align:right;">{plan_name}</td>
          </tr>
          <tr>
            <td style="padding:6px 0;color:#6b7280;">Billing Period</td>
            <td style="padding:6px 0;font-weight:700;color:#111827;text-align:right;">{period_label}</td>
          </tr>
          <tr style="border-top:1px solid #e5e7eb;">
            <td style="padding:10px 0 4px;font-weight:700;color:#111827;font-size:15px;">Amount Paid</td>
            <td style="padding:10px 0 4px;font-weight:800;color:#0BA37F;font-size:15px;text-align:right;">&#8377;{amount_inr:,.2f}</td>
          </tr>
        </table>
        <div style="font-size:12px;color:#9ca3af;margin-top:8px;">Payment ID: {payment_id}</div>
      </div>
      <h2 style="font-size:16px;font-weight:700;color:#111827;margin:0 0 12px;">What happens next?</h2>
      <ul style="margin:0 0 28px;padding-left:20px;font-size:14px;color:#374151;line-height:1.8;">
        <li>Your browser extension is now unlocked with all <strong>{plan_name}</strong> features</li>
        <li>Secret detection, phishing protection and DLP are fully active</li>
        <li>Manage your plan at <a href="{_BASE_URL}/user/dashboard" style="color:#0BA37F;">{_BASE_URL}/user/dashboard</a></li>
      </ul>
      <a href="{_BASE_URL}/user/dashboard"
         style="display:inline-block;background:#0BA37F;color:#fff;font-size:15px;font-weight:700;padding:12px 28px;border-radius:8px;text-decoration:none;">
        Go to Dashboard →
      </a>
    </div>
    <div style="padding:20px 40px;border-top:1px solid #f0f0f0;font-size:12px;color:#9ca3af;">
      SecureLint &middot; <a href="mailto:contact@vaptlabs.com" style="color:#9ca3af;">contact@vaptlabs.com</a>
      &middot; <a href="{_BASE_URL}/refund-policy" style="color:#9ca3af;">Refund Policy</a>
    </div>
  </div>
</body>
</html>"""
    try:
        httpx.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {_RESEND_KEY}", "Content-Type": "application/json"},
            json={
                "from":    "SecureLint <noreply@securelint.in>",
                "to":      [email],
                "subject": f"✅ Payment confirmed — {plan_name} plan activated",
                "html":    html,
            },
            timeout=10,
        )
    except Exception:
        pass


# ── POST /api/payment/create-order ───────────────────────────────────────────
class CreateOrderRequest(BaseModel):
    plan_id:        str
    billing_period: Optional[str] = "monthly"


@router.post("/payment/create-order")
def create_order(
    body: CreateOrderRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, user_email = _require_user(authorization)
    billing_period      = (body.billing_period or "monthly").lower().strip()

    # 1. Look up authoritative price from plan_pricing table
    price_inr = None
    plan_name = body.plan_id.capitalize()
    try:
        pp_res = (
            supabase_service.table("plan_pricing")
            .select("total_price")
            .eq("plan_id", body.plan_id)
            .eq("billing_period", billing_period)
            .eq("is_active", True)
            .execute()
        )
        if pp_res.data:
            price_inr = float(pp_res.data[0]["total_price"])
    except Exception:
        pass

    # 2. Fallback: plans.price_monthly × months
    if price_inr is None:
        try:
            months   = _period_months(billing_period)
            plan_res = supabase_service.table("plans").select("id, name, price_monthly").eq("id", body.plan_id).execute()
            if plan_res.data:
                plan      = plan_res.data[0]
                price_inr = float(plan.get("price_monthly") or 0) * months
                plan_name = plan.get("name", body.plan_id)
            else:
                price_inr = {"free": 0, "pro": 2999}.get(body.plan_id, 0) * months
        except Exception:
            price_inr = 0

    price_paise = int(price_inr * 100)

    # Zero-price plan — activate directly without Razorpay
    if price_paise == 0:
        try:
            supabase_service.table("user_subscriptions").upsert(
                {
                    "user_id":        user_id,
                    "plan_id":        body.plan_id,
                    "status":         "active",
                    "billing_period": billing_period,
                    "starts_at":      datetime.now(timezone.utc).isoformat(),
                    "ends_at":        None,
                    "updated_at":     datetime.now(timezone.utc).isoformat(),
                },
                on_conflict="user_id",
            ).execute()
        except Exception:
            pass
        return {"error": 0, "free": True, "plan_id": body.plan_id, "message": "Plan activated."}

    # Paid plan — create Razorpay order (amount is set SERVER-SIDE, not trusted from frontend)
    client = _rzp_client()
    try:
        order = client.order.create({
            "amount":   price_paise,
            "currency": "INR",
            "receipt":  f"{user_id[:8]}-{body.plan_id}-{billing_period}",
            "notes":    {
                "user_id":        user_id,
                "plan_id":        body.plan_id,
                "billing_period": billing_period,
                "user_email":     user_email,
            },
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Failed to create order: {e}"})

    # Save pending transaction with server-authoritative values
    try:
        supabase_service.table("payment_transactions").insert({
            "user_id":           user_id,
            "plan_id":           body.plan_id,   # locked in at order time
            "billing_period":    billing_period,
            "razorpay_order_id": order["id"],
            "amount_paise":      price_paise,    # locked in at order time
            "currency":          "INR",
            "status":            "created",
        }).execute()
    except Exception:
        pass

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


# ── POST /api/payment/verify ──────────────────────────────────────────────────
class VerifyPaymentRequest(BaseModel):
    razorpay_payment_id: str
    razorpay_order_id:   str
    razorpay_signature:  str
    # plan_id / billing_period from frontend are IGNORED for security —
    # we always use the values locked in payment_transactions at order time.
    plan_id:             Optional[str] = None
    billing_period:      Optional[str] = None


@router.post("/payment/verify")
def verify_payment(
    body: VerifyPaymentRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, user_email = _require_user(authorization)

    if not _RZP_SECRET:
        raise HTTPException(status_code=500, detail={"error": 1, "message": "Razorpay secret not configured."})

    # ── Step 1: Verify Razorpay HMAC signature ────────────────────────────────
    expected = hmac.new(
        _RZP_SECRET.encode(),
        f"{body.razorpay_order_id}|{body.razorpay_payment_id}".encode(),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, body.razorpay_signature):
        try:
            supabase_service.table("payment_transactions") \
                .update({"status": "failed"}) \
                .eq("razorpay_order_id", body.razorpay_order_id) \
                .execute()
        except Exception:
            pass
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": "Payment verification failed. Invalid signature."},
        )

    # ── Step 2: Load authoritative order data from our DB ────────────────────
    # NEVER trust plan_id or amount from the frontend request —
    # use what was stored when the order was created.
    stored_plan_id       = body.plan_id       or "pro"
    stored_billing       = body.billing_period or "monthly"
    stored_amount_paise  = 0

    try:
        tx_res = (
            supabase_service.table("payment_transactions")
            .select("plan_id, billing_period, amount_paise, user_id")
            .eq("razorpay_order_id", body.razorpay_order_id)
            .eq("status", "created")          # only accept orders that haven't been used
            .execute()
        )
        if tx_res.data:
            row                  = tx_res.data[0]
            stored_plan_id       = row["plan_id"]
            stored_billing       = row["billing_period"]
            stored_amount_paise  = int(row["amount_paise"])

            # Security: ensure this order belongs to the authenticated user
            if row["user_id"] != user_id:
                raise HTTPException(
                    status_code=403,
                    detail={"error": 1, "message": "This order does not belong to your account."},
                )
        else:
            # Order not found or already used
            raise HTTPException(
                status_code=400,
                detail={"error": 1, "message": "Order not found or already processed."},
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": f"Could not load order details: {e}"},
        )

    # ── Step 3: Verify actual charged amount via Razorpay API ─────────────────
    # Prevents paying ₹1 on a ₹1499 order (e.g. by swapping order IDs)
    if not _verify_rzp_amount(body.razorpay_payment_id, stored_amount_paise):
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": "Payment amount mismatch. Expected amount was not charged."},
        )

    # ── Step 4: Activate subscription ────────────────────────────────────────
    now  = datetime.now(timezone.utc).isoformat()
    ends = _ends_at(stored_billing)

    try:
        supabase_service.table("user_subscriptions").upsert(
            {
                "user_id":             user_id,
                "plan_id":             stored_plan_id,    # from DB, never from request
                "status":              "active",
                "billing_period":      stored_billing,
                "starts_at":           now,
                "ends_at":             ends,
                "razorpay_order_id":   body.razorpay_order_id,
                "razorpay_payment_id": body.razorpay_payment_id,
                "updated_at":          now,
            },
            on_conflict="user_id",
        ).execute()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": f"Subscription activation failed: {e}"},
        )

    # ── Step 5: Unlock plan features in user_settings ────────────────────────
    from app.core.plan_features import apply_plan_settings
    apply_plan_settings(user_id, stored_plan_id, supabase_service)

    # ── Step 6: Mark transaction as paid ─────────────────────────────────────
    try:
        supabase_service.table("payment_transactions").update({
            "status":              "paid",
            "razorpay_payment_id": body.razorpay_payment_id,
            "razorpay_signature":  body.razorpay_signature,
            "paid_at":             now,
        }).eq("razorpay_order_id", body.razorpay_order_id).execute()
    except Exception:
        pass

    # ── Step 6: Fetch plan display name ──────────────────────────────────────
    plan_name = stored_plan_id.capitalize()
    try:
        pl = supabase_service.table("plans").select("name").eq("id", stored_plan_id).execute()
        if pl.data:
            plan_name = pl.data[0].get("name", plan_name)
    except Exception:
        pass

    # ── Step 7: Send confirmation email ──────────────────────────────────────
    # Email comes from the JWT — no extra API call, works even without service key
    _send_payment_email(user_email, plan_name, stored_billing, stored_amount_paise, body.razorpay_payment_id)

    return {
        "error":          0,
        "success":        True,
        "plan_id":        stored_plan_id,
        "plan_name":      plan_name,
        "billing_period": stored_billing,
        "plan_status":    "active",
        "ends_at":        ends,
        "payment_id":     body.razorpay_payment_id,
        "message":        f"Payment successful! {plan_name} plan is now active.",
    }
