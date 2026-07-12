import os
import json as _json
from fastapi import APIRouter, Depends
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt
from app.core.plan_features import build_settings_row, _get_all_features

router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
supabase_service = create_client(SUPABASE_URL, _SERVICE_KEY) if _SERVICE_KEY else supabase

# Array-type columns — preserve as-is when masking
_ARRAY_COLUMNS = {"waf_social_domain", "email_dlp_domain", "enterprise_email_domains",
                  "site_exclusions", "phish_site_whitelist", "phish_mail_whitelist",
                  "session_domains"}

# Maps each Controls page control_id → user_settings fields it owns
_CONTROL_FIELDS = {
    "phishing_site":       ["phish_detection", "phish_detection_alert", "phish_detection_block",
                            "link_hover_detection", "domain_age_alert", "phish_site_whitelist"],
    "phishing_mail":       ["phish_mail_detection", "phish_mail_action", "phish_mail_whitelist"],
    "waf_domain":          ["waf_social_domain"],
    "session_theft":       ["session_marker", "session_domains"],
    "malicious_extension": ["blacklist_extension", "blacklist_extension_status"],
    "email_dlp":           ["email_dlp_enabled", "email_dlp_domain", "email_dlp_action"],
    "secret_masking":      ["global_masking_status", "masking_style", "mask_console",
                            "auto_mask_textareas", "auto_mask_inputs", "auto_mask_editor",
                            "overlay_input", "overlay_textarea", "overlay_editor",
                            "block_network_secrets", "block_form_submission",
                            "site_exclusions", "site_exclusions_status"],
}


def _mask_all_features(settings: dict, supabase_client) -> dict:
    """
    Returns a copy of settings with all boolean feature flags set to False.
    Array columns are preserved as-is (None / []).
    Non-boolean fields (masking_style, Plans, etc.) are also preserved.
    """
    boolean_cols = _get_all_features(supabase_client)
    masked = dict(settings)
    for col in boolean_cols:
        if col in masked and col not in _ARRAY_COLUMNS:
            masked[col] = False
    return masked


def _apply_org_controls(user_id: str, user_settings: dict, supabase_client) -> dict:
    """
    Enterprise-only: overlays the org admin's control configuration onto the
    user's settings, gated by the user's group membership (control_groups).

    Logic per control:
      - control_groups[ctrl] is empty / missing  → applies to ALL org members
      - control_groups[ctrl] has group IDs       → applies only to members in those groups
    If user is NOT in the required groups, all features for that control are
    disabled / cleared in the response.

    Returns a (possibly modified) copy of user_settings.
    """
    try:
        # 1. Resolve the user's org
        org_res = (
            supabase_client.table("organization_members")
            .select("org_id")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        if not org_res.data:
            return user_settings
        org_id = org_res.data[0]["org_id"]

        # 2. Find the org admin / owner
        admin_res = (
            supabase_client.table("organization_members")
            .select("user_id, role")
            .eq("org_id", org_id)
            .in_("role", ["admin", "owner"])
            .limit(1)
            .execute()
        )
        if not admin_res.data:
            return user_settings
        admin_uid = admin_res.data[0]["user_id"]

        # 3. Get admin's user_settings
        admin_st_res = (
            supabase_client.table("user_settings")
            .select("*")
            .eq("user_id", admin_uid)
            .execute()
        )
        if not admin_st_res.data:
            return user_settings
        admin_st = admin_st_res.data[0]

        # 4. Only Enterprise orgs get group-based controls
        plan = (admin_st.get("Plans") or "").lower()
        if plan != "enterprise":
            return user_settings

        # 5. User's group memberships in this org
        ug_res = (
            supabase_client.table("org_group_members")
            .select("group_id")
            .eq("org_id", org_id)
            .eq("user_id", user_id)
            .execute()
        )
        user_group_ids: set = {row["group_id"] for row in (ug_res.data or [])}

        # 6. control_groups from admin settings (may be stored as JSON string)
        raw_cg = admin_st.get("control_groups") or {}
        if isinstance(raw_cg, str):
            try:
                raw_cg = _json.loads(raw_cg)
            except Exception:
                raw_cg = {}
        control_groups: dict = raw_cg if isinstance(raw_cg, dict) else {}

        result = dict(user_settings)

        # 7. Overlay admin control config, gated by group membership
        for ctrl_id, fields in _CONTROL_FIELDS.items():
            allowed_group_ids = control_groups.get(ctrl_id) or []

            # No group restriction → all org members get this control
            if not allowed_group_ids:
                user_has_access = True
            else:
                user_has_access = bool(user_group_ids.intersection(set(allowed_group_ids)))

            for field in fields:
                if field not in admin_st:
                    continue
                admin_val = admin_st[field]
                if user_has_access:
                    result[field] = admin_val
                else:
                    # Disable / clear the feature for users outside the group
                    if isinstance(admin_val, bool):
                        result[field] = False
                    elif isinstance(admin_val, list):
                        result[field] = []
                    elif isinstance(admin_val, dict):
                        result[field] = {}
                    else:
                        result[field] = None

        return result

    except Exception as exc:
        print(f"[org_controls] error for user {user_id}: {exc}")
        return user_settings


@router.get("/settings")
def get_settings(user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    # ── Fetch user_settings row ───────────────────────────────────────────────
    res = supabase_service.table("user_settings").select("*").eq("user_id", user_id).execute()

    if not res.data:
        try:
            sub_res = supabase_service.table("user_subscriptions").select("plan_id").eq("user_id", user_id).limit(1).execute()
            plan_id = sub_res.data[0]["plan_id"] if sub_res.data else "free"
        except Exception:
            plan_id = "free"

        default_row = build_settings_row(user_id, plan_id, supabase_service)
        try:
            supabase_service.table("user_settings").insert(default_row).execute()
        except Exception:
            pass
        settings = default_row
    else:
        settings = res.data[0]

    # ── Check subscription status ─────────────────────────────────────────────
    is_active = False
    plan_id = settings.get("Plans", "free")
    try:
        sub_res = (
            supabase_service
            .table("user_subscriptions")
            .select("plan_id, status")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        if sub_res.data:
            is_active = sub_res.data[0].get("status") == "active"
            plan_id   = sub_res.data[0].get("plan_id", plan_id)
    except Exception:
        pass

    # ── Gate: return real settings only if subscription is active ─────────────
    if not is_active:
        result = _mask_all_features(settings, supabase_service)
    else:
        result = dict(settings)
        # Enterprise: overlay group-based org control settings
        if plan_id and plan_id.lower() == "enterprise":
            result = _apply_org_controls(user_id, result, supabase_service)

    result["subscription_active"] = is_active
    result["plan_id"]             = plan_id
    return result


@router.put("/settings")
def update_settings(updates: dict, user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    # Only allow columns that exist in user_settings
    boolean_cols = set(_get_all_features(supabase_service))
    non_boolean_allowed = {"masking_style", "site_exclusions", "waf_social_domain",
                           "enterprise_email_domains", "email_dlp_domain",
                           "email_dlp_action", "IT_mail", "Plans",
                           "session_marker", "session_domains",
                           "phish_site_whitelist", "phish_mail_whitelist",
                           "control_groups"}
    allowed_fields = boolean_cols | non_boolean_allowed

    clean_updates = {k: v for k, v in updates.items() if k in allowed_fields}

    if not clean_updates:
        return {"success": False, "message": "No valid settings fields provided"}

    # Ensure row exists
    exists = supabase_service.table("user_settings").select("user_id").eq("user_id", user_id).execute()
    if not exists.data:
        supabase_service.table("user_settings").insert({"user_id": user_id}).execute()

    # Serialize JSONB fields
    for col in {"control_groups"}:
        if col in clean_updates and isinstance(clean_updates[col], (dict, list)):
            clean_updates[col] = _json.dumps(clean_updates[col])

    supabase_service.table("user_settings").update(clean_updates).eq("user_id", user_id).execute()

    return {"success": True, "updated": clean_updates}
