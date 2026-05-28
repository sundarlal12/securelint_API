from fastapi import APIRouter, Depends
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt

from fastapi import APIRouter, Depends, Body
from supabase import create_client
from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt
from fastapi import HTTPException, Depends
router = APIRouter()
supabase = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)


# @router.get("/settings")
# def get_settings(user=Depends(verify_supabase_jwt)):
#     user_id = user["sub"]

#     res = (
#         supabase
#         .table("user_settings")
#         .select("*")
#         .eq("user_id", user_id)
#         .execute()
#     )

#     if not res.data:
#         # auto-create default settings (all features off for new users)
#         default = {
#             "user_id":                   user_id,
#             "Plans":                     None,
#             "enable_detection":          False,
#             "auto_mask_critical":        False,
#             "show_notifications":        False,
#             "mask_console":              False,
#             "scan_large_docs":           False,
#             "realtime_updates":          False,
#             "show_risk_score":           False,
#             "show_recent_activity":      False,
#             "animated_charts":           False,
#             "auto_refresh":              False,
#             "preserve_context":          False,
#             "auto_mask_textareas":       False,
#             "auto_mask_inputs":          False,
#             "overlay_input":             False,
#             "overlay_textarea":          False,
#             "overlay_editor":            False,
#             "block_network_secrets":     False,
#             "block_form_submission":     False,
#             "aggressive_email_blocking": False,
#             "detect_critical":           False,
#             "detect_high":               False,
#             "detect_medium":             False,
#             "detect_low":                False,
#             "notify_critical":           False,
#             "notify_high":               False,
#         }
#         supabase.table("user_settings").insert(default).execute()
#         return default

#     return res.data[0]




@router.get("/settings")
def get_settings(user=Depends(verify_supabase_jwt)):
    user_id = user["sub"]

    # Validate user still exists
    auth_user = supabase.auth.admin.get_user_by_id(user_id)

    if not auth_user or not auth_user.user:
        raise HTTPException(
            status_code=401,
            detail="User does not exist or account was deleted"
        )

    # Get settings
    res = (
        supabase
        .table("user_settings")
        .select("*")
        .eq("user_id", user_id)
        .execute()
    )

    if not res.data:
        # auto-create default settings
        default = {
            "user_id":                   user_id,
            "Plans":                     None,
            "enable_detection":          False,
            "auto_mask_critical":        False,
            "show_notifications":        False,
            "mask_console":              False,
            "scan_large_docs":           False,
            "realtime_updates":          False,
            "show_risk_score":           False,
            "show_recent_activity":      False,
            "animated_charts":           False,
            "auto_refresh":              False,
            "preserve_context":          False,
            "auto_mask_textareas":       False,
            "auto_mask_inputs":          False,
            "overlay_input":             False,
            "overlay_textarea":          False,
            "overlay_editor":            False,
            "block_network_secrets":     False,
            "block_form_submission":     False,
            "aggressive_email_blocking": False,
            "detect_critical":           False,
            "detect_high":               False,
            "detect_medium":             False,
            "detect_low":                False,
            "notify_critical":           False,
            "notify_high":               False,
        }

        try:
            supabase.table("user_settings").insert(default).execute()
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Failed to create user settings"
            )

        return default

    return res.data[0]


# @router.put("/settings")
# def update_settings(
#     updates: dict,
#     user=Depends(verify_supabase_jwt)
# ):
#     user_id = user["sub"]

#     # ensure row exists
#     existing = (
#         supabase
#         .table("user_settings")
#         .select("user_id")
#         .eq("user_id", user_id)
#         .execute()
#     )

#     if not existing.data:
#         supabase.table("user_settings").insert({
#             "user_id": user_id
#         }).execute()

#     supabase.table("user_settings") \
#         .update(updates) \
#         .eq("user_id", user_id) \
#         .execute()

#     return {"success": True}


@router.put("/settings")
def update_settings(
    updates: dict,
    user=Depends(verify_supabase_jwt)
):
    user_id = user["sub"]

    # ✅ EXACT columns from your table
    allowed_fields = {
        "Plans",
        "show_risk_score",
        "show_recent_activity",
        "animated_charts",
        "auto_refresh",

        "enable_detection",
        "auto_mask_critical",
        "show_notifications",
        "mask_console",
        "scan_large_docs",
        "realtime_updates",

        "masking_style",
        "preserve_context",
        "auto_mask_textareas",
        "auto_mask_inputs",

        "overlay_input",
        "overlay_textarea",
        "overlay_editor",

        "block_network_secrets",
        "block_form_submission",
        "aggressive_email_blocking",

        "detect_critical",
        "detect_high",
        "detect_medium",
        "detect_low",

        "notify_critical",
        "notify_high",
    }

    # filter only valid columns
    clean_updates = {
        k: v for k, v in updates.items()
        if k in allowed_fields
    }

    if not clean_updates:
        return {
            "success": False,
            "message": "No valid settings fields provided"
        }

    # ensure row exists
    exists = (
        supabase
        .table("user_settings")
        .select("user_id")
        .eq("user_id", user_id)
        .execute()
    )

    if not exists.data:
        supabase.table("user_settings").insert({
            "user_id": user_id
        }).execute()

    supabase.table("user_settings") \
        .update(clean_updates) \
        .eq("user_id", user_id) \
        .execute()

    return {
        "success": True,
        "updated": clean_updates
    }
