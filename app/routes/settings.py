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

# Columns that are never boolean — keep as-is during masking
_ARRAY_COLUMNS = {
    "waf_social_domain", "email_dlp_domain", "enterprise_email_domains",
    "site_exclusions", "phish_site_whitelist", "phish_mail_whitelist",
    "session_domains",
}


# ── Helper: mask all boolean features to False (inactive subscription) ────────

def _mask_all_features(settings: dict, supabase_client) -> dict:
    boolean_cols = _get_all_features(supabase_client)
    masked = dict(settings)
    for col in boolean_cols:
        if col in masked and col not in _ARRAY_COLUMNS:
            masked[col] = False
    return masked


# ── Helper: resolve enterprise group policy for a non-admin org member ────────

def _resolve_enterprise_settings(user_id: str, supabase_client) -> dict | None:
    """
    For Enterprise org employees only:
      1. Find the user's org.
      2. Verify the org admin has an active Enterprise subscription.
      3. Find the user's single group in this org.
      4. Fetch that group's enterprise_group_policy.settings.
      5. Return that policy dict AS-IS — enterprise employees are served
         exclusively from enterprise_group_policy, never merged/blended
         with any user_settings row (admin's or their own).

    Returns:
      None  — not an enterprise employee; caller uses own user_settings
      {}    — enterprise employee but no group / no policy → all-False safe default
      dict  — the group's enterprise_group_policy.settings, unmodified
    """
    try:
        sb = supabase_client

        # ── 1. Org membership ────────────────────────────────────────────────
        org_res = (
            sb.table("organization_members")
            .select("org_id, role")
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        if not org_res.data:
            return None
        org_id    = org_res.data[0]["org_id"]
        user_role = org_res.data[0].get("role", "employee")

        # Admins / owners are not subject to group policy — use their own row
        if user_role in ("admin", "owner"):
            return None

        # ── 2. Org admin + subscription check ───────────────────────────────
        admin_res = (
            sb.table("organization_members")
            .select("user_id")
            .eq("org_id", org_id)
            .in_("role", ["admin", "owner"])
            .limit(1)
            .execute()
        )
        if not admin_res.data:
            return None
        admin_uid = admin_res.data[0]["user_id"]

        sub_res = (
            sb.table("user_subscriptions")
            .select("status, plan_id")
            .eq("user_id", admin_uid)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        if not sub_res.data:
            return {}   # no sub on admin → no enterprise features for employees
        sub = sub_res.data[0]
        if sub.get("status") != "active" or (sub.get("plan_id") or "").lower() != "enterprise":
            return {}   # not active Enterprise → employees get all-False

        # ── 3. User's group in this org ─────────────────────────────────────
        grp_res = (
            sb.table("org_group_members")
            .select("group_id")
            .eq("org_id", org_id)
            .eq("user_id", user_id)
            .limit(1)
            .execute()
        )
        if not grp_res.data:
            return {}   # Not in any group → all-False, no policy to read from
        group_id = grp_res.data[0]["group_id"]

        # ── 4. Fetch enterprise_group_policy for that group ──────────────────
        pol_res = (
            sb.table("enterprise_group_policy")
            .select("settings")
            .eq("group_id", group_id)
            .eq("org_id", org_id)
            .execute()
        )
        if not pol_res.data:
            return {}   # Group exists but no policy configured yet → all-False

        raw = pol_res.data[0].get("settings", {})
        # Guard against legacy double-encoded string values
        while isinstance(raw, str):
            try:
                raw = _json.loads(raw)
            except Exception:
                raw = {}
                break
        group_policy: dict = raw if isinstance(raw, dict) else {}

        # ── 5. Normalise blacklist_extension in group policy ─────────────────
        _bl = group_policy.get("blacklist_extension")
        if isinstance(_bl, dict):
            # Strip numeric keys left by old character-spread bug
            ids_list = _bl.get("ids") if isinstance(_bl.get("ids"), list) else [
                v for k, v in _bl.items() if k.isdigit() and isinstance(v, str)
            ]
            group_policy["blacklist_extension"] = {
                "ids":    ids_list,
                "action": _bl.get("action", "detect"),
            }

        # ── 6. Return the policy settings AS-IS — no merge with user_settings ─
        return group_policy

    except Exception as exc:
        print(f"[enterprise_settings] error for user {user_id}: {exc}")
        return None   # unexpected error → fall back to own settings


# ── GET /settings ─────────────────────────────────────────────────────────────

@router.get("/settings")
def get_settings(user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    # Fetch own user_settings row
    res = supabase_service.table("user_settings").select("*").eq("user_id", user_id).execute()

    if not res.data:
        try:
            sub_res = (
                supabase_service.table("user_subscriptions")
                .select("plan_id").eq("user_id", user_id).limit(1).execute()
            )
            plan_id = sub_res.data[0]["plan_id"] if sub_res.data else "free"
        except Exception:
            plan_id = "free"
        default_row = build_settings_row(user_id, plan_id, supabase_service)
        try:
            supabase_service.table("user_settings").insert(default_row).execute()
        except Exception:
            pass
        own_settings = default_row
    else:
        own_settings = res.data[0]

    # Check own subscription
    is_active = False
    plan_id   = own_settings.get("Plans", "free")
    try:
        sub_res = (
            supabase_service.table("user_subscriptions")
            .select("plan_id, status").eq("user_id", user_id).limit(1).execute()
        )
        if sub_res.data:
            is_active = sub_res.data[0].get("status") == "active"
            plan_id   = sub_res.data[0].get("plan_id", plan_id)
    except Exception:
        pass

    # Org employees are ALWAYS governed by their org's group policy —
    # this takes priority over any personal subscription row they might
    # also happen to have (e.g. they self-signed-up before being invited).
    # _resolve_enterprise_settings() returns None for admins/owners and for
    # users who aren't in any org, so those fall through to their own row.
    enterprise_settings = _resolve_enterprise_settings(user_id, supabase_service)

    if enterprise_settings is not None:
        if enterprise_settings:
            # Enterprise employee with a configured group policy.
            # The policy only carries actual control fields — identity/
            # metadata fields (user_id, updated_at, Plans) aren't policy
            # content, so fill those from the employee's own row, same
            # as any other user.
            result = enterprise_settings
            result["user_id"]    = user_id
            result["updated_at"] = own_settings.get("updated_at")
            result["Plans"]      = own_settings.get("Plans", "Enterprise")
            is_active = True  # treated as active for the extension
        else:
            # Enterprise employee but org admin isn't active-Enterprise,
            # or no group / no policy configured → all-False
            result = _mask_all_features(own_settings, supabase_service)
    elif is_active:
        # Not an org employee (or is admin/owner) — own active subscription
        result = dict(own_settings)
    else:
        # No own subscription and not an enterprise employee — mask everything
        result = _mask_all_features(own_settings, supabase_service)

    result["subscription_active"] = is_active
    result["plan_id"]             = plan_id
    result.pop("control_groups", None)  # internal-only, not exposed to the extension
    return result


# ── PUT /settings (user-side update — limited fields) ─────────────────────────

@router.put("/settings")
def update_settings(updates: dict, user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    boolean_cols = set(_get_all_features(supabase_service))
    non_boolean_allowed = {
        "masking_style", "site_exclusions", "waf_social_domain",
        "enterprise_email_domains", "email_dlp_domain",
        "email_dlp_action", "IT_mail", "Plans",
        "session_marker", "session_domains",
        "phish_site_whitelist", "phish_mail_whitelist",
        "control_groups",
    }
    allowed_fields = boolean_cols | non_boolean_allowed
    clean_updates  = {k: v for k, v in updates.items() if k in allowed_fields}

    if not clean_updates:
        return {"success": False, "message": "No valid settings fields provided"}

    exists = supabase_service.table("user_settings").select("user_id").eq("user_id", user_id).execute()
    if not exists.data:
        supabase_service.table("user_settings").insert({"user_id": user_id}).execute()

    # supabase-py v2 handles dicts as JSONB natively — no json.dumps needed.

    supabase_service.table("user_settings").update(clean_updates).eq("user_id", user_id).execute()
    return {"success": True, "updated": clean_updates}
