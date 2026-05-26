from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr
from supabase import create_client
from typing import Optional
import os
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


class EnterpriseSalesContact(BaseModel):
    work_email:        EmailStr
    first_name:        str
    last_name:         str
    phone:             str
    company_name:      str
    company_size:      str   # "1-49" | "50-249" | "250-4999" | "5000+"
    function:          str   # Engineering | IT | Sales | etc.
    management_level:  str   # C-Level | VP-Level | Director | Manager | Non-Manager
    country:           str
    message:           Optional[str] = None
    marketing_consent: Optional[bool] = False


# ── POST /api/contact/sales ────────────────────────────────────────────────────
@router.post("/contact/sales")
def submit_sales_contact(body: EnterpriseSalesContact):
    """
    Saves an enterprise sales contact form submission to the
    enterprise_sales_contacts table.
    """
    row = {
        "work_email":        body.work_email,
        "first_name":        body.first_name.strip(),
        "last_name":         body.last_name.strip(),
        "phone":             body.phone.strip(),
        "company_name":      body.company_name.strip(),
        "company_size":      body.company_size,
        "function":          body.function,
        "management_level":  body.management_level,
        "country":           body.country,
        "message":           (body.message or "").strip() or None,
        "marketing_consent": body.marketing_consent or False,
        "status":            "new",
    }
    try:
        res = supabase_service.table("enterprise_sales_contacts").insert(row).execute()
        if not res.data:
            raise Exception("Insert returned no data")
        return {
            "error":   0,
            "success": True,
            "message": "Thank you! Our enterprise sales team will be in touch within 1 business day.",
        }
    except Exception as e:
        print(f"[contact/sales] insert error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": "Failed to submit. Please try again or email contact@vaptlabs.com"},
        )
