from fastapi import APIRouter, HTTPException, Header, Request
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from supabase import create_client
from typing import Optional, Tuple
from datetime import datetime, timedelta, timezone
import os, hmac, hashlib, razorpay, httpx
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.routes.coupons import _compute_discount

router = APIRouter()

_SERVICE_KEY    = os.getenv("SUPABASE_SERVICE_KEY", "")
_RZP_KEY_ID     = os.getenv("RAZORPAY_KEY_ID", "")
_RZP_SECRET     = os.getenv("RAZORPAY_KEY_SECRET", "")
_RESEND_KEY     = os.getenv("RESEND_API_KEY", "")
_BASE_URL       = os.getenv("BASE_URL", "https://securelint.in")
_API_PUBLIC_URL = os.getenv("API_PUBLIC_URL", "https://securelint-api.vercel.app")
_PP_CLIENT_ID   = os.getenv("PAYPAL_CLIENT_ID", "")
_PP_SECRET      = os.getenv("PAYPAL_SECRET", "")
_PP_BASE        = os.getenv("PAYPAL_BASE_URL", "")
_PP_MODE        = os.getenv("PAYPAL_MODE", "live").lower().strip()
_PP_USD_INR     = float(os.getenv("PAYPAL_USD_INR_RATE", "83"))
_GPAY_ENV       = os.getenv("GPAY_ENVIRONMENT", "")
_PAYU_KEY       = os.getenv("PAYU_KEY", "")
_PAYU_SALT      = os.getenv("PAYU_SALT", "")
_PAYU_BASE      = os.getenv("PAYU_BASE_URL", "")
_PAYU_SUCCESS   = os.getenv("PAYU_SUCCESS_URL", "")
_PAYU_FAIL      = os.getenv("PAYU_FAIL_URL",    "")

# ── DodoPayments — keys read fresh per-request (avoids Vercel import-cache) ───
_DODO_USD_INR = float(os.getenv("DODO_USD_INR_RATE", "94"))

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


def _apply_coupon(coupon_code: Optional[str], user_id: str,
                  plan_id: str, billing_period: str,
                  original_paise: int) -> tuple[int, int, Optional[dict], Optional[str]]:
    """
    Validate a coupon and atomically claim it via the claim_coupon() Postgres RPC.
    The RPC locks the coupon row, re-checks limits, increments current_uses,
    and inserts a 'pending' redemption record — all in one transaction.

    Returns (discount_paise, final_paise, coupon_row_or_None, redemption_id_or_None).
    Raises HTTPException(400) if the code is invalid or the claim fails.
    """
    if not coupon_code:
        return 0, original_paise, None, None

    code = coupon_code.strip().upper()
    try:
        res = supabase_service.table("coupons").select("*").ilike("code", code).limit(1).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Coupon lookup failed: {e}"})

    if not res.data:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Invalid coupon code."})

    coupon = res.data[0]

    # Fast pre-flight checks (expiry, plans, periods) before hitting the RPC
    from app.routes.coupons import _validate_coupon_row as _preflight
    err = _preflight(coupon, user_id, plan_id, billing_period, original_paise)
    if err:
        raise HTTPException(status_code=400, detail={"error": 1, "message": err})

    discount_paise = _compute_discount(coupon, original_paise)
    final_paise    = original_paise - discount_paise

    # Atomic claim via Postgres RPC — prevents race conditions and double-spend
    try:
        rpc_res = supabase_service.rpc("claim_coupon", {
            "p_coupon_id":      coupon["id"],
            "p_user_id":        user_id,
            "p_plan_id":        plan_id,
            "p_billing_period": billing_period,
            "p_original_paise": original_paise,
            "p_discount_paise": discount_paise,
            "p_final_paise":    final_paise,
            "p_currency":       "INR",
        }).execute()
        result = rpc_res.data
        if isinstance(result, list):
            result = result[0] if result else {}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Coupon claim failed: {e}"})

    if not result or not result.get("ok"):
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": result.get("error", "Coupon could not be applied.")},
        )

    redemption_id = result.get("redemption_id")
    return discount_paise, final_paise, coupon, redemption_id


def _commit_coupon_redemption(redemption_id: Optional[str],
                               payment_transaction_id: Optional[str]) -> None:
    """
    Move a pending coupon redemption to 'committed' after payment is confirmed.
    Uses the commit_coupon() Postgres RPC for atomicity.
    Best-effort — never raises.
    """
    if not redemption_id or not payment_transaction_id:
        return
    try:
        supabase_service.rpc("commit_coupon", {
            "p_redemption_id":          redemption_id,
            "p_payment_transaction_id": str(payment_transaction_id),
        }).execute()
    except Exception:
        pass


def _release_coupon_redemption(redemption_id: Optional[str]) -> None:
    """
    Cancel a pending coupon redemption when an order is abandoned or payment fails.
    Decrements current_uses so the slot is freed for other users.
    Best-effort — never raises.
    """
    if not redemption_id:
        return
    try:
        supabase_service.rpc("release_coupon", {"p_redemption_id": redemption_id}).execute()
    except Exception:
        pass


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
    coupon_code:    Optional[str] = None


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
                price_inr = {"pro": 2999}.get(body.plan_id, 0) * months
        except Exception:
            price_inr = 0

    original_paise = int(price_inr * 100)

    # Apply coupon (server-side — raises 400 if invalid)
    discount_paise, price_paise, coupon, redemption_id = _apply_coupon(
        body.coupon_code, user_id, body.plan_id, billing_period, original_paise
    )

    # Zero-price plan (or 100% coupon) — activate directly without Razorpay
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
        if redemption_id:
            _commit_coupon_redemption(redemption_id, None)
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
    tx_row: dict = {
        "user_id":           user_id,
        "plan_id":           body.plan_id,
        "billing_period":    billing_period,
        "razorpay_order_id": order["id"],
        "amount_paise":      price_paise,
        "currency":          "INR",
        "status":            "created",
    }
    if coupon:
        tx_row["coupon_code"]       = coupon["code"]
        tx_row["coupon_id"]         = coupon["id"]
        tx_row["discount_paise"]    = discount_paise
        tx_row["original_paise"]    = original_paise
    if redemption_id:
        tx_row["coupon_redemption_id"] = redemption_id

    tx_id = None
    try:
        ins = supabase_service.table("payment_transactions").insert(tx_row).execute()
        if ins.data:
            tx_id = ins.data[0].get("id")
    except Exception:
        pass

    return {
        "error":           0,
        "order_id":        order["id"],
        "amount":          order["amount"],
        "currency":        order["currency"],
        "plan_id":         body.plan_id,
        "plan_name":       plan_name,
        "billing_period":  billing_period,
        "key_id":          _RZP_KEY_ID,
        "original_amount": original_paise,
        "discount_amount": discount_paise,
        "coupon_applied":  coupon["code"] if coupon else None,
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
    stored_coupon        = None
    stored_tx_id         = None

    try:
        tx_res = (
            supabase_service.table("payment_transactions")
            .select("id, plan_id, billing_period, amount_paise, original_paise, discount_paise, coupon_id, coupon_code, user_id")
            .eq("razorpay_order_id", body.razorpay_order_id)
            .eq("status", "created")          # only accept orders that haven't been used
            .execute()
        )
        if tx_res.data:
            row                  = tx_res.data[0]
            stored_plan_id       = row["plan_id"]
            stored_billing       = row["billing_period"]
            stored_amount_paise  = int(row["amount_paise"])
            stored_tx_id         = row.get("id")

            # Load coupon row if one was applied at order time
            if row.get("coupon_id"):
                try:
                    cr = supabase_service.table("coupons").select("*").eq("id", row["coupon_id"]).limit(1).execute()
                    stored_coupon = cr.data[0] if cr.data else None
                except Exception:
                    pass

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

    # ── Step 6b: Commit coupon redemption ────────────────────────────────────
    if stored_coupon:
        stored_redemption_id = tx_res.data[0].get("coupon_redemption_id")
        _commit_coupon_redemption(stored_redemption_id, str(stored_tx_id) if stored_tx_id else None)

    # ── Step 7: Fetch plan display name ──────────────────────────────────────
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


# ═══════════════════════════════════════════════════════════════════════════════
# PayPal helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _pp_default_api_base() -> str:
    if _PP_MODE == "sandbox":
        return "https://api-m.sandbox.paypal.com"
    return "https://api-m.paypal.com"


def _pp_api_base() -> str:
    """
    Resolve PayPal REST API host.
    Live:    https://api-m.paypal.com
    Sandbox: https://api-m.sandbox.paypal.com
    """
    base = (_PP_BASE or "").strip().rstrip("/")
    if base:
        lowered = base.lower()
        if "payu" in lowered or "razorpay" in lowered or "paypal.com" not in lowered:
            fallback = _pp_default_api_base()
            print(
                f"[paypal] ignoring invalid PAYPAL_BASE_URL={base!r}; "
                f"using {fallback}. Fix Vercel env PAYPAL_BASE_URL."
            )
            return fallback
        return base

    return _pp_default_api_base()


def _pp_access_token() -> str:
    """Exchange PayPal client_id + secret for a short-lived Bearer token."""
    needed = {"PAYPAL_CLIENT_ID": _PP_CLIENT_ID, "PAYPAL_SECRET": _PP_SECRET}
    missing = [k for k, v in needed.items() if not v]
    if missing:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": f"PayPal env vars not set: {', '.join(missing)}"},
        )
    api_base = _pp_api_base()
    try:
        resp = httpx.post(
            f"{api_base}/v1/oauth2/token",
            auth=(_PP_CLIENT_ID, _PP_SECRET),
            data={"grant_type": "client_credentials"},
            headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"PayPal auth failed: {e}"})


def _pp_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "Accept": "application/json"}


def _paypal_order_amount(price_inr: float) -> tuple[str, str, int]:
    """
    PayPal REST v2 does NOT support INR. Orders must be in USD (or another
    supported currency). The merchant account must be enabled for cross-border
    USD receipts in PayPal Business settings.
    """
    usd = round(price_inr / _PP_USD_INR, 2)
    return "USD", f"{usd:.2f}", int(usd * 100)


def _is_india_country(country: Optional[str]) -> bool:
    return (country or "").strip().lower() in {"india", "in"}


def _lookup_price(plan_id: str, billing_period: str) -> tuple[float, str]:
    """Return (price_inr, plan_name) from plan_pricing or plans tables."""
    plan_name = plan_id.capitalize()
    try:
        pp_res = (
            supabase_service.table("plan_pricing")
            .select("total_price")
            .eq("plan_id", plan_id)
            .eq("billing_period", billing_period)
            .eq("is_active", True)
            .execute()
        )
        if pp_res.data:
            return float(pp_res.data[0]["total_price"]), plan_name
    except Exception:
        pass
    try:
        months   = _period_months(billing_period)
        plan_res = supabase_service.table("plans").select("id, name, price_monthly").eq("id", plan_id).execute()
        if plan_res.data:
            plan      = plan_res.data[0]
            plan_name = plan.get("name", plan_id)
            return float(plan.get("price_monthly") or 0) * months, plan_name
    except Exception:
        pass
    return 0.0, plan_name


# ── POST /api/payment/paypal-create-order ────────────────────────────────────
class PayPalCreateOrderRequest(BaseModel):
    plan_id:        str
    billing_period: Optional[str] = "monthly"
    country:        Optional[str] = None
    coupon_code:    Optional[str] = None


@router.post("/payment/paypal-create-order")
def paypal_create_order(
    body: PayPalCreateOrderRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, _user_email = _require_user(authorization)
    if _is_india_country(body.country):
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": "PayPal is for international payments only. Use Razorpay for India."},
        )
    billing_period       = (body.billing_period or "monthly").lower().strip()

    price_inr, plan_name = _lookup_price(body.plan_id, billing_period)
    original_paise_pp    = int(price_inr * 100)
    discount_paise_pp, final_paise_pp, coupon_pp, redemption_id_pp = _apply_coupon(
        body.coupon_code, user_id, body.plan_id, billing_period, original_paise_pp
    )
    price_inr_after = final_paise_pp / 100

    currency_code, amount_str, amount_paise = _paypal_order_amount(price_inr_after)
    if float(amount_str) <= 0:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Invalid plan or zero price."})

    token = _pp_access_token()
    api_base = _pp_api_base()
    try:
        resp = httpx.post(
            f"{api_base}/v2/checkout/orders",
            headers=_pp_headers(token),
            json={
                "intent": "CAPTURE",
                "purchase_units": [{
                    "amount": {"currency_code": currency_code, "value": amount_str},
                    "description": f"SecureLint {plan_name} - {billing_period.capitalize()}",
                }],
            },
            timeout=15,
        )
        if not resp.is_success:
            raise HTTPException(
                status_code=500,
                detail={"error": 1, "message": f"PayPal order error {resp.status_code}: {resp.text}"},
            )
        order_data = resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Failed to create PayPal order: {e}"})

    # Save pending transaction so verify can look up authoritative values
    pp_tx_row: dict = {
        "user_id":         user_id,
        "plan_id":         body.plan_id,
        "billing_period":  billing_period,
        "paypal_order_id": order_data["id"],
        "amount_paise":    amount_paise,
        "amount_usd":      float(amount_str) if currency_code == "USD" else None,
        "currency":        currency_code,
        "status":          "created",
        "gateway":         "paypal",
    }
    if coupon_pp:
        pp_tx_row["coupon_code"]    = coupon_pp["code"]
        pp_tx_row["coupon_id"]      = coupon_pp["id"]
        pp_tx_row["discount_paise"] = discount_paise_pp
        pp_tx_row["original_paise"] = original_paise_pp
    if redemption_id_pp:
        pp_tx_row["coupon_redemption_id"] = redemption_id_pp
    try:
        supabase_service.table("payment_transactions").insert(pp_tx_row).execute()
    except Exception:
        pass

    return {
        "error":           0,
        "order_id":        order_data["id"],
        "amount":          amount_str,
        "currency":        currency_code,
        "amount_usd":      float(amount_str) if currency_code == "USD" else None,
        "plan_id":         body.plan_id,
        "plan_name":       plan_name,
        "original_amount": original_paise_pp,
        "discount_amount": discount_paise_pp,
        "coupon_applied":  coupon_pp["code"] if coupon_pp else None,
    }


# ── POST /api/payment/paypal-verify ──────────────────────────────────────────
class PayPalVerifyRequest(BaseModel):
    paypal_order_id: str
    plan_id:         Optional[str] = None
    billing_period:  Optional[str] = None
    country:         Optional[str] = None


@router.post("/payment/paypal-verify")
def verify_paypal_payment(
    body: PayPalVerifyRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, user_email = _require_user(authorization)

    if _is_india_country(body.country):
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": "PayPal is for international payments only. Use Razorpay for India."},
        )

    # ── Step 1: Confirm order is COMPLETED with PayPal ────────────────────────
    token = _pp_access_token()
    api_base = _pp_api_base()
    try:
        resp = httpx.get(
            f"{api_base}/v2/checkout/orders/{body.paypal_order_id}",
            headers=_pp_headers(token),
            timeout=15,
        )
        if not resp.is_success:
            raise HTTPException(
                status_code=500,
                detail={"error": 1, "message": f"PayPal lookup error {resp.status_code}: {resp.text}"},
            )
        order_data = resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"PayPal order lookup failed: {e}"})

    if order_data.get("status") != "COMPLETED":
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": f"PayPal order not completed. Status: {order_data.get('status')}"},
        )

    # ── Step 2: Load authoritative values from our DB ─────────────────────────
    stored_plan_id    = body.plan_id       or "pro"
    stored_billing    = body.billing_period or "monthly"
    stored_amount_paise = 0
    stored_currency   = "USD"

    try:
        tx_res = (
            supabase_service.table("payment_transactions")
            .select("plan_id, billing_period, amount_paise, amount_usd, currency, user_id")
            .eq("paypal_order_id", body.paypal_order_id)
            .eq("status", "created")
            .execute()
        )
        if tx_res.data:
            row                 = tx_res.data[0]
            stored_plan_id      = row["plan_id"]
            stored_billing      = row["billing_period"]
            stored_amount_paise = int(row.get("amount_paise") or 0)
            stored_currency     = (row.get("currency") or "USD").upper()
            if stored_amount_paise <= 0 and row.get("amount_usd"):
                stored_amount_paise = int(float(row["amount_usd"]) * 100)
                stored_currency = "USD"
            if row["user_id"] != user_id:
                raise HTTPException(
                    status_code=403,
                    detail={"error": 1, "message": "This order does not belong to your account."},
                )
        else:
            raise HTTPException(
                status_code=400,
                detail={"error": 1, "message": "Order not found or already processed."},
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Could not load order details: {e}"})

    # ── Step 3: Verify captured amount matches what we expect ─────────────────
    try:
        captures      = order_data["purchase_units"][0]["payments"]["captures"]
        paid_amount   = float(captures[0]["amount"]["value"])
        paid_currency = (captures[0]["amount"].get("currency_code") or stored_currency).upper()
        expected      = stored_amount_paise / 100
        if stored_amount_paise > 0:
            if paid_currency == "INR" and paid_amount < expected - 1:
                raise HTTPException(
                    status_code=400,
                    detail={"error": 1, "message": f"Amount mismatch: expected ₹{expected:.2f}, got ₹{paid_amount:.2f}."},
                )
            if paid_currency == "USD" and paid_amount < expected - 0.02:
                raise HTTPException(
                    status_code=400,
                    detail={"error": 1, "message": f"Amount mismatch: expected ${expected:.2f}, got ${paid_amount:.2f}."},
                )
    except HTTPException:
        raise
    except Exception:
        pass  # If we can't parse, PayPal already confirmed COMPLETED — proceed

    # ── Step 4: Activate subscription ────────────────────────────────────────
    now  = datetime.now(timezone.utc).isoformat()
    ends = _ends_at(stored_billing)

    try:
        supabase_service.table("user_subscriptions").upsert(
            {
                "user_id":         user_id,
                "plan_id":         stored_plan_id,
                "status":          "active",
                "billing_period":  stored_billing,
                "starts_at":       now,
                "ends_at":         ends,
                "paypal_order_id": body.paypal_order_id,
                "updated_at":      now,
            },
            on_conflict="user_id",
        ).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Subscription activation failed: {e}"})

    # ── Step 5: Apply plan feature flags ─────────────────────────────────────
    from app.core.plan_features import apply_plan_settings
    apply_plan_settings(user_id, stored_plan_id, supabase_service)

    # ── Step 6: Mark transaction paid ────────────────────────────────────────
    try:
        supabase_service.table("payment_transactions").update(
            {"status": "paid", "paid_at": now}
        ).eq("paypal_order_id", body.paypal_order_id).execute()
    except Exception:
        pass

    # ── Step 7: Fetch display name + send email ───────────────────────────────
    plan_name = stored_plan_id.capitalize()
    try:
        pl = supabase_service.table("plans").select("name").eq("id", stored_plan_id).execute()
        if pl.data:
            plan_name = pl.data[0].get("name", plan_name)
    except Exception:
        pass

    _send_payment_email(
        user_email, plan_name, stored_billing,
        int(_lookup_price(stored_plan_id, stored_billing)[0] * 100),
        body.paypal_order_id,
    )

    return {
        "error":          0,
        "success":        True,
        "plan_id":        stored_plan_id,
        "plan_name":      plan_name,
        "billing_period": stored_billing,
        "plan_status":    "active",
        "ends_at":        ends,
        "payment_id":     body.paypal_order_id,
        "message":        f"Payment successful! {plan_name} plan is now active.",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# Google Pay
# ═══════════════════════════════════════════════════════════════════════════════

class GooglePayVerifyRequest(BaseModel):
    payment_token:  str
    plan_id:        Optional[str] = None
    billing_period: Optional[str] = None
    country:        Optional[str] = None


@router.post("/payment/googlepay-verify")
def verify_googlepay_payment(
    body: GooglePayVerifyRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, user_email = _require_user(authorization)

    stored_plan_id = (body.plan_id       or "pro").lower().strip()
    stored_billing = (body.billing_period or "monthly").lower().strip()

    # ── Token verification ────────────────────────────────────────────────────
    # TEST mode  : The "example" gateway returns a dummy token — nothing to verify.
    # PRODUCTION : Replace this block with your payment gateway's token processing.
    #   e.g. Stripe:     stripe.PaymentMethod.create(type="card", card={"token": body.payment_token})
    #   e.g. Braintree:  gateway.transaction.sale({"payment_method_nonce": body.payment_token, ...})
    if not _GPAY_ENV:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": "GPAY_ENVIRONMENT env var not set."},
        )
    if _GPAY_ENV.upper() != "TEST":
        raise HTTPException(
            status_code=501,
            detail={"error": 1, "message": "Google Pay production gateway not yet configured."},
        )

    price_inr, plan_name = _lookup_price(stored_plan_id, stored_billing)
    now  = datetime.now(timezone.utc).isoformat()
    ends = _ends_at(stored_billing)

    # ── Record transaction ────────────────────────────────────────────────────
    try:
        supabase_service.table("payment_transactions").insert({
            "user_id":        user_id,
            "plan_id":        stored_plan_id,
            "billing_period": stored_billing,
            "amount_paise":   int(price_inr * 100),
            "currency":       "USD",
            "status":         "paid",
            "paid_at":        now,
            "gateway":        "googlepay",
        }).execute()
    except Exception:
        pass

    # ── Activate subscription ─────────────────────────────────────────────────
    try:
        supabase_service.table("user_subscriptions").upsert(
            {
                "user_id":        user_id,
                "plan_id":        stored_plan_id,
                "status":         "active",
                "billing_period": stored_billing,
                "starts_at":      now,
                "ends_at":        ends,
                "updated_at":     now,
            },
            on_conflict="user_id",
        ).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Subscription activation failed: {e}"})

    # ── Apply plan feature flags ──────────────────────────────────────────────
    from app.core.plan_features import apply_plan_settings
    apply_plan_settings(user_id, stored_plan_id, supabase_service)

    _send_payment_email(
        user_email, plan_name, stored_billing,
        int(price_inr * 100),
        f"gpay-{user_id[:8]}",
    )

    return {
        "error":          0,
        "success":        True,
        "plan_id":        stored_plan_id,
        "plan_name":      plan_name,
        "billing_period": stored_billing,
        "plan_status":    "active",
        "ends_at":        ends,
        "message":        f"Payment successful! {plan_name} plan is now active.",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# PayU Money  (hash-based redirect flow — works for India and international)
# Docs: https://devguide.payu.in/
# ═══════════════════════════════════════════════════════════════════════════════

def _payu_hash(txnid: str, amount: str, productinfo: str,
               firstname: str, email: str) -> str:
    """
    PayU forward hash:
    SHA512( key|txnid|amount|productinfo|firstname|email|udf1..udf10||||||SALT )
    All udf fields are empty for us.
    """
    import hashlib
    raw = f"{_PAYU_KEY}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{_PAYU_SALT}"
    return hashlib.sha512(raw.encode("utf-8")).hexdigest()


def _payu_verify_hash(txnid: str, amount: str, productinfo: str,
                      firstname: str, email: str, status: str,
                      posted_hash: str,
                      udf1: str = "", udf2: str = "", udf3: str = "",
                      udf4: str = "", udf5: str = "") -> bool:
    """
    PayU reverse hash (response):
    SHA512(SALT|status||||||udf5|udf4|udf3|udf2|udf1|email|firstname|productinfo|amount|txnid|key)
    """
    import hashlib
    import json

    raw = (
        f"{_PAYU_SALT}|{status}||||||{udf5}|{udf4}|{udf3}|{udf2}|{udf1}|"
        f"{email}|{firstname}|{productinfo}|{amount}|{txnid}|{_PAYU_KEY}"
    )
    expected = hashlib.sha512(raw.encode("utf-8")).hexdigest()
    if posted_hash == expected:
        return True

    # PayU may send v1/v2 hash JSON for newer integrations.
    try:
        parsed = json.loads(posted_hash)
        if isinstance(parsed, dict):
            return parsed.get("v1") == expected or parsed.get("v2") == expected
    except (json.JSONDecodeError, TypeError):
        pass
    return False


# ── POST /api/payment/payu-create-order ──────────────────────────────────────
class PayUCreateOrderRequest(BaseModel):
    plan_id:        str
    billing_period: Optional[str] = "monthly"
    full_name:      Optional[str] = ""
    country:        Optional[str] = ""
    phone:          Optional[str] = ""
    coupon_code:    Optional[str] = None


def _payu_default_success_url() -> str:
    # PayU browser POST must hit the API directly — Vercel Python can fail on
    # proxied form bodies from Netlify. Netlify route remains as a fallback.
    return f"{_API_PUBLIC_URL.rstrip('/')}/api/payment/payu-success"


def _payu_default_fail_url() -> str:
    return f"{_API_PUBLIC_URL.rstrip('/')}/api/payment/payu-failure"


def _parse_urlencoded_form(body: bytes) -> dict[str, str]:
    """Parse PayU application/x-www-form-urlencoded POST body."""
    from urllib.parse import parse_qs

    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {k: (v[0] if v else "") for k, v in parsed.items()}


def _payu_success_url() -> str:
    return _PAYU_SUCCESS or _payu_default_success_url()


def _payu_fail_url() -> str:
    return _PAYU_FAIL or _payu_default_fail_url()


def _payu_sanitize_name(name: str) -> tuple[str, str]:
    cleaned = " ".join(name.strip().split())
    if not cleaned:
        return "Customer", ""
    parts = cleaned.split(" ", 1)
    firstname = parts[0][:60]
    lastname = (parts[1] if len(parts) > 1 else "")[:60]
    return firstname, lastname


def _payu_sanitize_productinfo(plan_name: str, billing_period: str) -> str:
    label = f"SecureLint {plan_name} {billing_period.capitalize()}"
    return label[:100]


def _payu_sanitize_phone(raw: str) -> str:
    digits = "".join(c for c in (raw or "") if c.isdigit())
    return digits[:15]


def _resolve_user_email(user_id: str, fallback_email: Optional[str] = None) -> str:
    """Prefer explicit email (PayU form / JWT); fall back to Supabase admin lookup."""
    email = (fallback_email or "").strip()
    if email:
        return email
    try:
        user_res = supabase_service.auth.admin.get_user_by_id(user_id)
        return user_res.user.email or ""
    except Exception:
        return ""


def _payu_txn_amount_paise(row: dict, plan_id: str, billing_period: str) -> int:
    stored = int(row.get("amount_paise") or 0)
    if stored > 0:
        return stored
    price_inr, _ = _lookup_price(plan_id, billing_period)
    return int(price_inr * 100)


def _payu_validate_credentials() -> None:
    """Fail fast on common PayU env misconfiguration."""
    if _PAYU_KEY and _PAYU_SALT and _PAYU_KEY == _PAYU_SALT:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": "PAYU_SALT must differ from PAYU_KEY. Copy both from the PayU dashboard."},
        )
    base = (_PAYU_BASE or "").lower()
    if base and "test.payu.in" in base and "secure.payu.in" not in base:
        return
    if base and "secure.payu.in" in base and _PAYU_KEY == "1Gg1ic":
        raise HTTPException(
            status_code=500,
            detail={
                "error": 1,
                "message": "PayU test key (1Gg1ic) cannot be used with secure.payu.in. Set live PAYU_KEY/PAYU_SALT on Vercel.",
            },
        )


@router.post("/payment/payu-create-order")
def payu_create_order(
    body: PayUCreateOrderRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, user_email = _require_user(authorization)
    needed = {"PAYU_KEY": _PAYU_KEY, "PAYU_SALT": _PAYU_SALT, "PAYU_BASE_URL": _PAYU_BASE}
    missing = [k for k, v in needed.items() if not v]
    if missing:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": f"PayU env vars not set: {', '.join(missing)}"},
        )
    _payu_validate_credentials()

    billing_period = (body.billing_period or "monthly").lower().strip()
    price_inr, plan_name = _lookup_price(body.plan_id, billing_period)
    if price_inr <= 0:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Invalid plan or zero price."})

    # Apply coupon before computing hash — amount must be final before hash
    payu_original_paise = int(price_inr * 100)
    payu_discount_paise, payu_final_paise, coupon_payu, redemption_id_payu = _apply_coupon(
        body.coupon_code, user_id, body.plan_id, billing_period, payu_original_paise
    )
    price_inr = payu_final_paise / 100

    # PayU India expects INR unless multi-currency is explicitly enabled on the merchant account.
    amount_str = f"{price_inr:.2f}"

    phone = _payu_sanitize_phone(body.phone or "")
    if len(phone) < 10:
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": "Please enter a valid 10-digit phone number for PayU."},
        )

    import uuid
    txnid = f"SL{uuid.uuid4().hex[:18].upper()}"
    productinfo = _payu_sanitize_productinfo(plan_name, billing_period)
    firstname, lastname = _payu_sanitize_name(body.full_name or user_email.split("@")[0] or "Customer")

    hash_val = _payu_hash(txnid, amount_str, productinfo, firstname, user_email)

    # Save pending transaction — required for payu-success callback activation.
    payu_tx_row: dict = {
        "user_id":        user_id,
        "plan_id":        body.plan_id,
        "billing_period": billing_period,
        "payu_txnid":     txnid,
        "amount_paise":   payu_final_paise,
        "currency":       "INR",
        "status":         "created",
        "gateway":        "payu",
    }
    if coupon_payu:
        payu_tx_row["coupon_code"]    = coupon_payu["code"]
        payu_tx_row["coupon_id"]      = coupon_payu["id"]
        payu_tx_row["discount_paise"] = payu_discount_paise
        payu_tx_row["original_paise"] = payu_original_paise
    if redemption_id_payu:
        payu_tx_row["coupon_redemption_id"] = redemption_id_payu
    try:
        supabase_service.table("payment_transactions").insert(payu_tx_row).execute()
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": f"Could not record PayU transaction: {e}"},
        )

    # PayU requires a POST form submission — return params for frontend to POST
    return {
        "error":           0,
        "action_url":      f"{_PAYU_BASE}/_payment",
        "original_amount": payu_original_paise,
        "discount_amount": payu_discount_paise,
        "coupon_applied":  coupon_payu["code"] if coupon_payu else None,
        "params": {
            "key":         _PAYU_KEY,
            "txnid":       txnid,
            "amount":      amount_str,
            "productinfo": productinfo,
            "firstname":   firstname,
            "lastname":    lastname,
            "email":       user_email,
            "phone":       phone,
            # Always use API callback routes — PayU POSTs form data here after payment.
            # Vercel PAYU_SUCCESS_URL / PAYU_FAIL_URL env vars are not used for hosted checkout.
            "surl":        _payu_default_success_url(),
            "furl":        _payu_default_fail_url(),
            "hash":        hash_val,
        },
        "txnid":      txnid,
        "amount_inr": price_inr,
        "plan_id":    body.plan_id,
        "plan_name":  plan_name,
    }


def _activate_payu_subscription(
    txnid: str,
    *,
    mihpayid: str = "",
    skip_user_check: bool = False,
    expected_user_id: Optional[str] = None,
    fallback_email: Optional[str] = None,
) -> dict:
    """Load a pending PayU txn and activate the subscription."""
    try:
        tx_res = (
            supabase_service.table("payment_transactions")
            .select("plan_id, billing_period, user_id, amount_paise")
            .eq("payu_txnid", txnid)
            .eq("status", "created")
            .execute()
        )
        if not tx_res.data:
            paid_res = (
                supabase_service.table("payment_transactions")
                .select("plan_id, billing_period, user_id, amount_paise")
                .eq("payu_txnid", txnid)
                .eq("status", "paid")
                .execute()
            )
            if paid_res.data:
                row = paid_res.data[0]
                if not skip_user_check and expected_user_id and row["user_id"] != expected_user_id:
                    raise HTTPException(
                        status_code=403,
                        detail={"error": 1, "message": "This transaction does not belong to your account."},
                    )
                return {
                    "error":          0,
                    "success":        True,
                    "plan_id":        row["plan_id"],
                    "plan_name":      row["plan_id"].capitalize(),
                    "billing_period": row["billing_period"],
                    "plan_status":    "active",
                    "payment_id":     mihpayid or txnid,
                    "message":        "Subscription already active.",
                }
            raise HTTPException(
                status_code=400,
                detail={"error": 1, "message": "Transaction not found or already processed."},
            )
        row = tx_res.data[0]
        if not skip_user_check and expected_user_id and row["user_id"] != expected_user_id:
            raise HTTPException(
                status_code=403,
                detail={"error": 1, "message": "This transaction does not belong to your account."},
            )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Could not load transaction: {e}"})

    user_id = row["user_id"]
    stored_plan_id = row["plan_id"]
    stored_billing = row["billing_period"]
    user_email = _resolve_user_email(user_id, fallback_email)

    now  = datetime.now(timezone.utc).isoformat()
    ends = _ends_at(stored_billing)

    try:
        supabase_service.table("user_subscriptions").upsert(
            {
                "user_id":        user_id,
                "plan_id":        stored_plan_id,
                "status":         "active",
                "billing_period": stored_billing,
                "starts_at":      now,
                "ends_at":        ends,
                "updated_at":     now,
            },
            on_conflict="user_id",
        ).execute()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": 1, "message": f"Subscription activation failed: {e}"})

    from app.core.plan_features import apply_plan_settings
    apply_plan_settings(user_id, stored_plan_id, supabase_service)

    try:
        supabase_service.table("payment_transactions").update({
            "status":        "paid",
            "paid_at":       now,
            "payu_mihpayid": mihpayid or "",
        }).eq("payu_txnid", txnid).execute()
    except Exception:
        pass

    plan_name = stored_plan_id.capitalize()
    try:
        pl = supabase_service.table("plans").select("name").eq("id", stored_plan_id).execute()
        if pl.data:
            plan_name = pl.data[0].get("name", plan_name)
    except Exception:
        pass

    if user_email:
        amount_paise = _payu_txn_amount_paise(row, stored_plan_id, stored_billing)
        _send_payment_email(
            user_email,
            plan_name,
            stored_billing,
            amount_paise,
            mihpayid or txnid,
        )

    return {
        "error":          0,
        "success":        True,
        "plan_id":        stored_plan_id,
        "plan_name":      plan_name,
        "billing_period": stored_billing,
        "plan_status":    "active",
        "ends_at":        ends,
        "payment_id":     mihpayid or txnid,
        "message":        f"Payment successful! {plan_name} plan is now active.",
    }


@router.post("/payment/payu-success")
async def payu_success_callback(request: Request):
    """PayU POSTs here after a successful payment."""
    try:
        form = _parse_urlencoded_form(await request.body())
    except Exception as e:
        print(f"[payu-success] form parse error: {e}")
        return RedirectResponse(f"{_BASE_URL}/user/dashboard/billing?payu=failed", status_code=303)

    txnid = str(form.get("txnid") or "")
    status = str(form.get("status") or "")
    posted_hash = str(form.get("hash") or "")
    amount = str(form.get("amount") or "")
    productinfo = str(form.get("productinfo") or "")
    firstname = str(form.get("firstname") or "")
    email = str(form.get("email") or "")
    mihpayid = str(form.get("mihpayid") or "")
    udf1 = str(form.get("udf1") or "")
    udf2 = str(form.get("udf2") or "")
    udf3 = str(form.get("udf3") or "")
    udf4 = str(form.get("udf4") or "")
    udf5 = str(form.get("udf5") or "")

    if not txnid:
        return RedirectResponse(f"{_BASE_URL}/user/dashboard/billing?payu=failed", status_code=303)

    try:
        if posted_hash and status and amount and productinfo and firstname and email:
            if not _payu_verify_hash(
                txnid, amount, productinfo, firstname, email, status, posted_hash,
                udf1, udf2, udf3, udf4, udf5,
            ):
                return RedirectResponse(f"{_BASE_URL}/user/dashboard/billing?payu=invalid", status_code=303)
            if status.lower() != "success":
                return RedirectResponse(f"{_BASE_URL}/user/dashboard/billing?payu=failed", status_code=303)

        result = _activate_payu_subscription(
            txnid,
            mihpayid=mihpayid,
            skip_user_check=True,
            fallback_email=email,
        )
    except HTTPException:
        return RedirectResponse(f"{_BASE_URL}/user/dashboard/billing?payu=failed", status_code=303)
    except Exception as e:
        print(f"[payu-success] activation error for txnid={txnid}: {e}")
        return RedirectResponse(
            f"{_BASE_URL}/user/dashboard/subscription?payu=success&txnid={txnid}",
            status_code=303,
        )

    plan_id = result.get("plan_id", "pro")
    return RedirectResponse(
        f"{_BASE_URL}/user/dashboard/subscription?payu=success&txnid={txnid}&plan_id={plan_id}",
        status_code=303,
    )


@router.post("/payment/payu-failure")
async def payu_failure_callback(request: Request):
    """PayU POSTs here after a failed/cancelled payment."""
    return RedirectResponse(f"{_BASE_URL}/user/dashboard/billing?payu=failed", status_code=303)


# ── POST /api/payment/payu-verify ────────────────────────────────────────────
# Called after PayU redirects back to success URL, OR as a server-to-server
# callback (PayU webhook).  Accepts both the redirect POST params and our
# own verification payload.
class PayUVerifyRequest(BaseModel):
    txnid:          str
    mihpayid:       Optional[str] = None    # PayU payment ID
    status:         Optional[str] = None    # success | failure | pending
    hash:           Optional[str] = None    # PayU response hash
    amount:         Optional[str] = None
    productinfo:    Optional[str] = None
    firstname:      Optional[str] = None
    email:          Optional[str] = None
    plan_id:        Optional[str] = None
    billing_period: Optional[str] = None


@router.post("/payment/payu-verify")
def verify_payu_payment(
    body: PayUVerifyRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, user_email = _require_user(authorization)

    # ── Step 1: Verify hash ───────────────────────────────────────────────────
    if body.hash and body.status and body.amount and body.productinfo and body.firstname and body.email:
        if not _payu_verify_hash(
            body.txnid, body.amount, body.productinfo,
            body.firstname, body.email, body.status, body.hash,
        ):
            raise HTTPException(
                status_code=400,
                detail={"error": 1, "message": "PayU signature verification failed."},
            )
        if body.status.lower() != "success":
            raise HTTPException(
                status_code=400,
                detail={"error": 1, "message": f"Payment not successful. Status: {body.status}"},
            )

    return _activate_payu_subscription(
        body.txnid,
        mihpayid=body.mihpayid or "",
        expected_user_id=user_id,
        fallback_email=user_email or body.email or "",
    )


# ══════════════════════════════════════════════════════════════════════════════
# DodoPayments — international checkout
# ══════════════════════════════════════════════════════════════════════════════

def _dodo_client():
    """Return an initialised DodoPayments SDK client. Reads env vars fresh each call."""
    api_key = os.getenv("DODO_PAYMENTS_API_KEY", "")
    env     = os.getenv("DODO_PAYMENTS_ENVIRONMENT", "live_mode")
    if not api_key:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": "DodoPayments API key not configured (DODO_PAYMENTS_API_KEY). Contact support."},
        )
    from dodopayments import DodoPayments as _DodoSDK
    return _DodoSDK(bearer_token=api_key, environment=env)


def _dodo_product_id(plan_id: str, billing_period: str) -> str:
    """
    Resolve DodoPayments product_id. Priority order:
      1. DODO_PRODUCT_{PLAN}_{PERIOD}  e.g. DODO_PRODUCT_PRO_MONTHLY
      2. DODO_PRODUCT_{PLAN}           e.g. DODO_PRODUCT_PRO  (one product for all periods)
      3. DODO_PRODUCT_ID               single PWYW product for every plan/period
    Recommended: create ONE product with Pay What You Want (PWYW) enabled
    and set DODO_PRODUCT_ID — the endpoint will pass the amount dynamically.
    """
    specific = os.getenv(f"DODO_PRODUCT_{plan_id.upper()}_{billing_period.upper()}", "")
    if specific:
        return specific
    plan_default = os.getenv(f"DODO_PRODUCT_{plan_id.upper()}", "")
    if plan_default:
        return plan_default
    return os.getenv("DODO_PRODUCT_ID", "")


def _send_dodo_payment_email(email: str, plan_name: str, billing_period: str,
                              amount_usd: float, payment_id: str) -> None:
    """Email confirmation for DodoPayments (USD amount)."""
    if not _RESEND_KEY or not email:
        return
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
          <tr><td style="padding:6px 0;color:#6b7280;">Plan</td>
              <td style="padding:6px 0;font-weight:700;color:#111827;text-align:right;">{plan_name}</td></tr>
          <tr><td style="padding:6px 0;color:#6b7280;">Billing Period</td>
              <td style="padding:6px 0;font-weight:700;color:#111827;text-align:right;">{period_label}</td></tr>
          <tr style="border-top:1px solid #e5e7eb;">
            <td style="padding:10px 0 4px;font-weight:700;color:#111827;font-size:15px;">Amount Paid</td>
            <td style="padding:10px 0 4px;font-weight:800;color:#0BA37F;font-size:15px;text-align:right;">${amount_usd:.2f} USD</td>
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


# ── POST /api/payment/dodo-create-order ───────────────────────────────────────

class DodoCreateOrderRequest(BaseModel):
    plan_id:        str
    billing_period: Optional[str] = "monthly"
    country:        Optional[str] = None
    full_name:      Optional[str] = None
    coupon_code:    Optional[str] = None


@router.post("/payment/dodo-create-order")
def dodo_create_order(
    body: DodoCreateOrderRequest,
    authorization: Optional[str] = Header(None),
):
    user_id, user_email = _require_user(authorization)

    if _is_india_country(body.country):
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": "DodoPayments is for international payments only. Use Razorpay for India."},
        )

    billing_period = (body.billing_period or "monthly").lower().strip()

    product_id = _dodo_product_id(body.plan_id, billing_period)
    if not product_id:
        raise HTTPException(
            status_code=400,
            detail={
                "error": 1,
                "message": (
                    f"DodoPayments product not configured for plan='{body.plan_id}' period='{billing_period}'. "
                    "Set one of these Vercel env vars: "
                    f"DODO_PRODUCT_{body.plan_id.upper()}_{billing_period.upper()} (specific), "
                    f"DODO_PRODUCT_{body.plan_id.upper()} (plan-wide), or "
                    "DODO_PRODUCT_ID (global fallback for all plans)."
                ),
            },
        )

    # Price reference (for logging; DodoPayments uses its own pre-set product price)
    price_inr, plan_name = _lookup_price(body.plan_id, billing_period)
    original_paise       = int(price_inr * 100)
    discount_paise, final_paise, coupon, redemption_id = _apply_coupon(
        body.coupon_code, user_id, body.plan_id, billing_period, original_paise
    )
    amount_usd = round((final_paise / 100) / _DODO_USD_INR, 2)

    client = _dodo_client()

    customer: dict = {"email": user_email}
    if body.full_name and body.full_name.strip():
        customer["name"] = body.full_name.strip()

    try:
        checkout = client.checkout_sessions.create(
            product_cart=[{
                "product_id": product_id,
                "quantity":   1,
                # No 'amount' field — price is set on the product in DodoPayments dashboard
            }],
            customer=customer,
            return_url=f"{_BASE_URL}/user/dashboard/subscription?dodo=success",
            billing_currency="USD",
            metadata={
                "user_id":        user_id,
                "plan_id":        body.plan_id,
                "billing_period": billing_period,
                "amount_usd":     str(amount_usd),
            },
        )
        checkout_url = checkout.checkout_url
        session_id   = getattr(checkout, "session_id", None)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": f"DodoPayments checkout creation failed: {e}"},
        )

    # Persist pending transaction
    tx_row: dict = {
        "user_id":          user_id,
        "plan_id":          body.plan_id,
        "billing_period":   billing_period,
        "dodo_session_id":  session_id,
        "amount_paise":     final_paise,
        "amount_usd":       amount_usd,
        "currency":         "USD",
        "status":           "created",
        "gateway":          "dodopayments",
    }
    if coupon:
        tx_row["coupon_code"]    = coupon["code"]
        tx_row["coupon_id"]      = coupon["id"]
        tx_row["discount_paise"] = discount_paise
        tx_row["original_paise"] = original_paise
    if redemption_id:
        tx_row["coupon_redemption_id"] = redemption_id
    try:
        supabase_service.table("payment_transactions").insert(tx_row).execute()
    except Exception:
        pass

    return {
        "error":        0,
        "checkout_url": checkout_url,
        "session_id":   session_id,
        "amount_usd":   amount_usd,
        "plan_name":    plan_name,
    }


# ── POST /api/payment/dodo-webhook ────────────────────────────────────────────

@router.post("/payment/dodo-webhook")
async def dodo_webhook(request: Request):
    """
    Receive DodoPayments webhook events.
    Register this URL in your DodoPayments dashboard:
        https://securelint-api.vercel.app/api/payment/dodo-webhook
    Handles: payment.succeeded, subscription.active
    """
    raw_body = await request.body()

    # Signature verification using webhook secret
    webhook_key = os.getenv("DODO_PAYMENTS_WEBHOOK_KEY", "")
    if webhook_key:
        try:
            from dodopayments.webhooks import WebhookVerifier
            verifier = WebhookVerifier(webhook_key)
            verifier.verify(raw_body, dict(request.headers))
        except Exception:
            raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid DodoPayments webhook signature."})

    try:
        import json as _json
        data = _json.loads(raw_body)
    except Exception:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Invalid JSON payload."})

    event_type = data.get("type", "")
    event_data = data.get("data", {})
    metadata   = event_data.get("metadata", {})

    user_id        = metadata.get("user_id")
    plan_id        = metadata.get("plan_id")
    billing_period = metadata.get("billing_period", "monthly")
    payment_id     = event_data.get("payment_id") or event_data.get("subscription_id", f"dodo_{user_id[:8] if user_id else 'na'}")

    if event_type in ("payment.succeeded", "subscription.active"):
        if not user_id or not plan_id:
            return {"ok": True}

        # Activate subscription in Supabase
        try:
            supabase_service.table("subscriptions").upsert(
                {
                    "user_id":        user_id,
                    "plan_id":        plan_id,
                    "billing_period": billing_period,
                    "status":         "active",
                    "ends_at":        _ends_at(billing_period),
                    "gateway":        "dodopayments",
                    "payment_id":     payment_id,
                },
                on_conflict="user_id",
            ).execute()
        except Exception:
            pass

        # Update users table
        try:
            supabase_service.table("users").update(
                {"plan_id": plan_id, "plan_status": "active"}
            ).eq("id", user_id).execute()
        except Exception:
            pass

        # Update payment_transactions status
        try:
            session_id = event_data.get("session_id")
            if session_id:
                supabase_service.table("payment_transactions").update(
                    {"status": "paid", "payment_id": payment_id}
                ).eq("dodo_session_id", session_id).execute()
        except Exception:
            pass

        # Send confirmation email
        try:
            user_res = supabase_service.table("users").select("email").eq("id", user_id).single().execute()
            if user_res.data:
                email = user_res.data.get("email", "")
                _, plan_name = _lookup_price(plan_id, billing_period)
                amount_usd   = float(metadata.get("amount_usd", 0))
                _send_dodo_payment_email(email, plan_name, billing_period, amount_usd, payment_id)
        except Exception:
            pass

    return {"ok": True}
