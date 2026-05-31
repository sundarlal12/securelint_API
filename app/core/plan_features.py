from typing import Any, Dict

# ── Feature flags per plan ────────────────────────────────────────────────────
# Each plan entry is the COMPLETE user_settings row for that tier.
# Higher tiers include everything from lower tiers.

_FREE_FLAGS: Dict[str, Any] = {
    "Plans":               "free",
    # Detection
    "enable_detection":    True,
    "detect_medium":       True,
    "detect_low":          True,
    # Notifications
    "show_notifications":  True,
    # Masking — basic inputs / textareas
    "auto_mask_inputs":    True,
    "auto_mask_textareas": True,
    # Overlays — basic
    "overlay_input":       True,
    "overlay_textarea":    True,
    # Dashboard display
    "show_risk_score":     True,
    "show_recent_activity":True,
    "masking_style":       "blur",
    # Pro/Enterprise flags all off
    "auto_mask_critical":          False,
    "auto_mask_editor":            False,
    "mask_console":                False,
    "overlay_editor":              False,
    "scan_large_docs":             False,
    "detect_critical":             False,
    "detect_high":                 False,
    "notify_critical":             False,
    "notify_high":                 False,
    "realtime_updates":            False,
    "animated_charts":             False,
    "auto_refresh":                False,
    "preserve_context":            False,
    "block_network_secrets":       False,
    "block_form_submission":       False,
   
    "global_masking_status":       False,
    # Enterprise flags off
    "aggressive_email_blocking":   False,
    "email_dlp_enabled":           False,
    "enterprise_data_collection":  False,
    "waf_social_domain":           False,
    # Pro flags off
    "password_breach_data":        False,
    "extension_scrape_data":       False,
    # Nullable data fields (present on all plans)
    "site_exclusions_status":      True,
}

_PRO_FLAGS: Dict[str, Any] = {
    **_FREE_FLAGS,
    "Plans":               "pro",
    # All pro features on
    "auto_mask_critical":          True,
    "auto_mask_editor":            True,
    "mask_console":                True,
    "overlay_editor":              True,
    "scan_large_docs":             True,
    "detect_critical":             True,
    "detect_high":                 True,
    "notify_critical":             True,
    "notify_high":                 True,
    "realtime_updates":            True,
    "animated_charts":             True,
    "auto_refresh":                True,
    "preserve_context":            True,
    "block_network_secrets":       True,
    "block_form_submission":       True,
    "site_exclusions_status":      True,
    "global_masking_status":       True,
    "password_breach_data":        True,
    "extension_scrape_data":       True,
}

_ENTERPRISE_FLAGS: Dict[str, Any] = {
    **_PRO_FLAGS,
    "Plans":               "enterprise",
    # Enterprise-only features
    "aggressive_email_blocking":   True,
    "email_dlp_enabled":           True,
    "enterprise_data_collection":  True,
    "waf_social_domain":           True,
}

PLAN_SETTINGS: Dict[str, Dict[str, Any]] = {
    "free":       _FREE_FLAGS,
    "pro":        _PRO_FLAGS,
    "enterprise": _ENTERPRISE_FLAGS,
}


def build_settings_row(user_id: str, plan_id: str) -> Dict[str, Any]:
    """
    Returns a complete user_settings dict ready to INSERT at signup.
    Falls back to free-tier flags for unknown plan_ids.
    """
    flags = PLAN_SETTINGS.get(plan_id.lower(), _FREE_FLAGS)
    return {"user_id": user_id, **flags}


def apply_plan_settings(user_id: str, plan_id: str, supabase_client) -> None:
    """
    Upserts user_settings with the full feature flags for plan_id.
    Called after a successful payment to unlock features.
    Never raises — logs errors but does not interrupt the payment response.
    """
    flags = PLAN_SETTINGS.get(plan_id.lower(), _FREE_FLAGS)
    row = {"user_id": user_id, **flags}
    try:
        supabase_client.table("user_settings").upsert(
            row, on_conflict="user_id"
        ).execute()
        print(f"[plan_features] settings applied for user={user_id} plan={plan_id}")
    except Exception as e:
        print(f"[plan_features] ERROR applying settings for user={user_id}: {e}")
