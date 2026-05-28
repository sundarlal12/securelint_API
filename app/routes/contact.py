from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, field_validator
from supabase import create_client
from typing import Optional
import os
import resend
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY

router = APIRouter()

_SERVICE_KEY  = os.getenv("SUPABASE_SERVICE_KEY", "")
_RESEND_KEY   = os.getenv("RESEND_API_KEY", "")
_NOTIFY_EMAIL = os.getenv("CONTACT_NOTIFY_EMAIL", "support@vaptlabs.com")

supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


# ── Email helper ──────────────────────────────────────────────────────────────

def _send_lead_notification(name: str, email_id: str, phone: str,
                             company: str, services: str, message: str) -> None:
    """
    Send a lead-notification email to the internal team via Resend.
    Best-effort — never raises, never blocks the API response.
    """
    if not _RESEND_KEY:
        print("[contactus] skipped lead email — RESEND_API_KEY not set")
        return
    try:
        resend.api_key = _RESEND_KEY

        html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>VAPTLabs Lead Notification</title>
</head>

<body style="
  margin:0;
  padding:40px 0;
  background:#eef2f7;
  font-family:Arial,Helvetica,sans-serif;
">

  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center">

        <!-- Main Container -->
        <table width="720" cellpadding="0" cellspacing="0"
          style="
          background:#ffffff;
          border-radius:28px;
          overflow:hidden;
          box-shadow:0 10px 35px rgba(15,23,42,0.08);
        ">

          <!-- Header -->
          <tr>
            <td style="padding:42px 50px 24px 50px;">

              <!-- Logo -->
              <img
                src="https://ik.imagekit.io/5biqvaptlabsnfbqw/vaptlabs1.png?updatedAt=1746055025044"
                alt="VAPTLabs"
                width="220"
                style="display:block;"
              />

            </td>
          </tr>

          <!-- Badge -->
          <tr>
            <td style="padding:0 50px;">

              <div style="
                display:inline-block;
                background:#fff1f2;
                color:#dc2626;
                padding:12px 22px;
                border-radius:999px;
                font-size:14px;
                font-weight:500;
              ">
                🛡️ Best VAPT Testing Service Provider in India
              </div>

            </td>
          </tr>

          <!-- Lead Notification -->
          <tr>
            <td style="padding:24px 50px 8px 50px;">

              <div style="
                background:#fff7ed;
                border:1px solid #fed7aa;
                color:#c2410c;
                padding:16px 20px;
                border-radius:16px;
                font-size:14px;
                line-height:1.8;
              ">
                A new VAPT service inquiry has been submitted through the
                VAPTLabs website. Please review the lead details and contact
                the client.
              </div>

            </td>
          </tr>

          <!-- Contact Information -->
          <tr>
            <td style="padding:24px 50px 42px 50px;">

              <table width="100%" cellpadding="0" cellspacing="0"
                style="border-collapse:separate;border-spacing:0 18px;">

                <!-- Full Name -->
                <tr>

                  <td width="190"
                    style="
                    background:#f8fafc;
                    padding:18px 22px;
                    border-radius:16px 0 0 16px;
                    color:#e11d48;
                    font-weight:700;
                    font-size:15px;
                    border:1px solid #e5e7eb;
                    vertical-align:top;
                  ">
                    Full Name
                  </td>

                  <td
                    style="
                    background:#ffffff;
                    padding:18px 22px;
                    border-radius:0 16px 16px 0;
                    border:1px solid #e5e7eb;
                  ">

                    <div style="
                      max-width:420px;
                      overflow-x:auto;
                      white-space:nowrap;
                      color:#0f172a;
                      font-size:15px;
                    ">
                      {{name}}
                    </div>

                  </td>

                </tr>

                <!-- Email -->
                <tr>

                  <td
                    style="
                    background:#f8fafc;
                    padding:18px 22px;
                    border-radius:16px 0 0 16px;
                    color:#e11d48;
                    font-weight:700;
                    font-size:15px;
                    border:1px solid #e5e7eb;
                    vertical-align:top;
                  ">
                    Email Address
                  </td>

                  <td
                    style="
                    background:#ffffff;
                    padding:18px 22px;
                    border-radius:0 16px 16px 0;
                    border:1px solid #e5e7eb;
                  ">

                    <div style="
                      max-width:420px;
                      overflow-x:auto;
                      white-space:nowrap;
                      color:#0f172a;
                      font-size:15px;
                    ">
                      {{emailId}}
                    </div>

                  </td>

                </tr>

                <!-- Phone -->
                <tr>

                  <td
                    style="
                    background:#f8fafc;
                    padding:18px 22px;
                    border-radius:16px 0 0 16px;
                    color:#e11d48;
                    font-weight:700;
                    font-size:15px;
                    border:1px solid #e5e7eb;
                    vertical-align:top;
                  ">
                    Phone Number
                  </td>

                  <td
                    style="
                    background:#ffffff;
                    padding:18px 22px;
                    border-radius:0 16px 16px 0;
                    border:1px solid #e5e7eb;
                  ">

                    <div style="
                      max-width:420px;
                      overflow-x:auto;
                      white-space:nowrap;
                      color:#0f172a;
                      font-size:15px;
                    ">
                      {{phone}}
                    </div>

                  </td>

                </tr>

                <!-- Company -->
                <tr>

                  <td
                    style="
                    background:#f8fafc;
                    padding:18px 22px;
                    border-radius:16px 0 0 16px;
                    color:#e11d48;
                    font-weight:700;
                    font-size:15px;
                    border:1px solid #e5e7eb;
                    vertical-align:top;
                  ">
                    Company
                  </td>

                  <td
                    style="
                    background:#ffffff;
                    padding:18px 22px;
                    border-radius:0 16px 16px 0;
                    border:1px solid #e5e7eb;
                  ">

                    <div style="
                      max-width:420px;
                      overflow-x:auto;
                      white-space:nowrap;
                      color:#0f172a;
                      font-size:15px;
                    ">
                      {{company}}
                    </div>

                  </td>

                </tr>

                <!-- Services -->
                <tr>

                  <td
                    style="
                    background:#f8fafc;
                    padding:18px 22px;
                    border-radius:16px 0 0 16px;
                    color:#e11d48;
                    font-weight:700;
                    font-size:15px;
                    border:1px solid #e5e7eb;
                    vertical-align:top;
                  ">
                    Requested Services
                  </td>

                  <td
                    style="
                    background:#ffffff;
                    padding:18px 22px;
                    border-radius:0 16px 16px 0;
                    border:1px solid #e5e7eb;
                  ">

                    <div style="
                      max-width:420px;
                      overflow:auto;
                      word-break:break-word;
                      white-space:pre-wrap;
                      color:#0f172a;
                      font-size:15px;
                      line-height:1.8;
                    ">
                      {{services}}
                    </div>

                  </td>

                </tr>

                <!-- Message -->
                <tr>

                  <td
                    style="
                    background:#f8fafc;
                    padding:18px 22px;
                    border-radius:16px 0 0 16px;
                    color:#e11d48;
                    font-weight:700;
                    font-size:15px;
                    border:1px solid #e5e7eb;
                    vertical-align:top;
                  ">
                    Message
                  </td>

                  <td
                    style="
                    background:#ffffff;
                    padding:18px 22px;
                    border-radius:0 16px 16px 0;
                    border:1px solid #e5e7eb;
                  ">

                    <div style="
                      max-width:420px;
                      overflow:auto;
                      word-break:break-word;
                      white-space:pre-wrap;
                      color:#0f172a;
                      font-size:15px;
                      line-height:1.9;
                    ">
                      {{message}}
                    </div>

                  </td>

                </tr>

              </table>

            </td>
          </tr>

          <!-- Compact CTA Buttons -->
          <tr>
            <td style="padding:0 50px 42px 50px;">

              <table cellpadding="0" cellspacing="0">
                <tr>

                  <!-- Reply Button -->
                  <td>
                    <a href="mailto:{{emailId}}"
                      style="
                      display:inline-block;
                      background:#be123c;
                      color:#ffffff;
                      text-decoration:none;
                      padding:12px 20px;
                      border-radius:10px;
                      font-size:14px;
                      font-weight:600;
                      line-height:1;
                    ">
                      Reply to Client
                    </a>
                  </td>

                  <td width="12"></td>

                  <!-- Website Button -->
                  <td>
                    <a href="https://vaptlabs.com"
                      style="
                      display:inline-block;
                      background:#ffffff;
                      color:#0f172a;
                      text-decoration:none;
                      padding:12px 20px;
                      border-radius:10px;
                      font-size:14px;
                      font-weight:600;
                      line-height:1;
                      border:1px solid #d1d5db;
                    ">
                      Open Website
                    </a>
                  </td>

                </tr>
              </table>

            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="
              padding:28px 50px;
              background:#f8fafc;
              border-top:1px solid #e5e7eb;
            ">

              <table width="100%">
                <tr>

                  <td align="left">

                    <p style="
                      margin:0;
                      color:#0f172a;
                      font-size:15px;
                      font-weight:700;
                    ">
                      VAPTLabs
                    </p>

                    <p style="
                      margin:8px 0 0 0;
                      color:#64748b;
                      font-size:13px;
                    ">
                      Website Lead Notification
                    </p>

                  </td>

                  <td align="right">

                    <p style="
                      margin:0;
                      color:#94a3b8;
                      font-size:12px;
                    ">
                      Auto Generated Email
                    </p>

                  </td>

                </tr>
              </table>

            </td>
          </tr>

        </table>

      </td>
    </tr>
  </table>

</body>
</html>"""

        result = resend.Emails.send({
            "from":    "VAPTLabs Leads <noreply@securelint.in>",
            "to":      [_NOTIFY_EMAIL],
            "subject": f"[VAPTLabs] New Security Lead | {company or 'Unknown Company'}",
            "html":    html_body,
            "reply_to": email_id,
        })
        print(f"[contactus] lead email sent → {_NOTIFY_EMAIL} | result: {result}")
    except Exception as e:
        print(f"[contactus] lead email FAILED: {e}")


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


# ── POST /api/contactus ───────────────────────────────────────────────────────

class ContactUsRequest(BaseModel):
    name:     str
    emailId:  EmailStr
    phone:    Optional[str] = None
    company:  Optional[str] = None
    message:  str
    services: Optional[str] = None   # comma-separated list of requested services

    @field_validator("name", "message", mode="before")
    @classmethod
    def must_not_be_blank(cls, v: str) -> str:
        if not v or not str(v).strip():
            raise ValueError("This field cannot be blank.")
        return str(v).strip()


@router.post("/contactus")
def contact_us(body: ContactUsRequest):
    """
    General contact-us form.
    Stores the enquiry in the contact_us_submissions table.

    Expected body:
        {
            "name":     "Sundar Lal",
            "emailId":  "sundar@vaptlabs.com",
            "phone":    "9414689978",        (optional)
            "company":  "VAPTLabs",          (optional)
            "message":  "Hello, I need…",
            "services": "Web app pentesting, Mobile app pentesting"  (optional)
        }
    """
    row = {
        "name":     body.name,
        "email":    str(body.emailId).lower().strip(),
        "phone":    (body.phone    or "").strip() or None,
        "company":  (body.company  or "").strip() or None,
        "message":  body.message,
        "services": (body.services or "").strip() or None,
        "status":   "new",
    }

    try:
        res = supabase_service.table("contact_us_submissions").insert(row).execute()
        if not res.data:
            raise Exception("Insert returned no data")
        print(f"[contactus] new submission from {row['email']}")
    except Exception as e:
        print(f"[contactus] insert error: {e}")
        raise HTTPException(
            status_code=500,
            detail={"error": 1, "message": "Failed to submit. Please try again or email contact@vaptlabs.com"},
        )

    # Send internal lead-notification email (best-effort, never blocks the response)
    _send_lead_notification(
        name     = body.name,
        email_id = str(body.emailId),
        phone    = body.phone    or "",
        company  = body.company  or "",
        services = body.services or "",
        message  = body.message,
    )

    return {
        "error":   0,
        "success": True,
        "message": "Thank you for reaching out! We'll get back to you within 1 business day.",
    }
