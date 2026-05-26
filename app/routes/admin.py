from fastapi import APIRouter, Depends, HTTPException, Query
from supabase import create_client
from typing import Optional
from pydantic import BaseModel
import os
from collections import defaultdict
from datetime import datetime, timezone, timedelta

from app.core.config import SUPABASE_URL, SUPABASE_ANON_KEY
from app.core.supabase_jwt import verify_supabase_jwt

router = APIRouter()

_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")

def _sb():
    """Fresh Supabase client per call — prevents HTTP/2 keep-alive disconnection errors."""
    key = _SERVICE_KEY if _SERVICE_KEY else SUPABASE_ANON_KEY
    return create_client(SUPABASE_URL, key)


def _to_iso(value: Optional[str], end_of_day: bool = False) -> Optional[str]:
    """
    Always extracts only the date part (YYYY-MM-DD) from whatever is supplied,
    then returns start-of-day (00:00:00) or end-of-day (23:59:59) accordingly.

    Accepts:
      - date-only           2026-05-16
      - full ISO datetime   2026-05-16T13:51:00.000Z  → date part 2026-05-16
      - URL-decoded form    2026-05-16T00%3A00%3A00.000Z (caller should decode first,
                            but we handle the T-split safely either way)
    """
    if not value:
        return None
    # Extract date portion only (everything before "T")
    date_part = value.split("T")[0].strip()
    try:
        d = datetime.strptime(date_part, "%Y-%m-%d")
        if end_of_day:
            d = d.replace(hour=23, minute=59, second=59, microsecond=999000)
        return d.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    except ValueError:
        return value  # pass through unchanged if unparseable


# ---------------------------------------------------------------------------
# Shared guard — every admin endpoint calls this first
# ---------------------------------------------------------------------------

def _require_admin(user: dict) -> dict:
    """
    Verifies the calling user is an active enterprise admin/owner.
    Returns {"user_id", "org_id", "role"} on success, raises 403 otherwise.
    """
    user_id = user.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail={"error": 1, "message": "Invalid token"})

    # Check enterprise plan
    sub_res = (
        _sb()
        .table("user_subscriptions")
        .select("plan_id, status")
        .eq("user_id", user_id)
        .execute()
    )
    if not sub_res.data:
        raise HTTPException(status_code=403, detail={"error": 1, "message": "No subscription found"})

    sub = sub_res.data[0]
    if sub.get("plan_id") != "enterprise" or sub.get("status") != "active":
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Enterprise plan required"})

    # Check admin/owner role
    org_res = (
        _sb()
        .table("organization_members")
        .select("org_id, role")
        .eq("user_id", user_id)
        .execute()
    )
    if not org_res.data:
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Not part of any organization"})

    membership = org_res.data[0]
    if membership.get("role") not in ("admin", "owner"):
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Admin or owner role required"})

    return {
        "user_id": user_id,
        "org_id": membership["org_id"],
        "role": membership["role"],
    }


def _fetch_org_incidents(org_id: str) -> list:
    """Fetch all incidents for the org, sorted newest first."""
    res = (
        _sb()
        .table("incidents")
        .select("*")
        .eq("org_id", org_id)
        .order("timestamp", desc=True)
        .execute()
    )
    return res.data or []


# ---------------------------------------------------------------------------
# GET /api/admin/dashboard  —  overview stats for the home dashboard
# ---------------------------------------------------------------------------

@router.get("/admin/dashboard")
def admin_dashboard(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    incidents = _fetch_org_incidents(org_id)

    # Team members count
    members_res = (
        _sb()
        .table("organization_members")
        .select("user_id, role")
        .eq("org_id", org_id)
        .execute()
    )
    members = members_res.data or []

    # Unique devices (browser_ids)
    devices = {i["browser_id"] for i in incidents if i.get("browser_id")}

    # Severity breakdown
    severity_counts = defaultdict(int)
    for inc in incidents:
        severity_counts[inc.get("severity", "unknown")] += 1

    # Incidents this week
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    this_week = [
        i for i in incidents
        if i.get("timestamp") and datetime.fromisoformat(
            i["timestamp"].replace("Z", "+00:00")
        ) >= week_ago
    ]

    # Blocked = action is "blocked" only; masked = action is "masked" only
    blocked  = [i for i in incidents if i.get("action") == "blocked"]
    masked   = [i for i in incidents if i.get("action") == "masked"]
    allowed  = [i for i in incidents if i.get("action") == "allowed"]
    flagged  = [i for i in incidents if i.get("action") == "flagged"]
    critical = [i for i in incidents if i.get("severity") == "critical"]

    action_breakdown = {
        "blocked": len(blocked),
        "masked":  len(masked),
        "allowed": len(allowed),
        "flagged": len(flagged),
    }

    # Top-5 most recent secret incidents (exclude url_visit / phishing / email_recipient)
    EXCLUDE_TYPES = {"url_visit", "phishing", "email_recipient"}
    secret_incidents = [
        i for i in incidents
        if i.get("secret_type", "").lower() not in EXCLUDE_TYPES
        and i.get("secret_type")
    ]
    # Sort by timestamp descending and take top 5
    def _ts(i: dict) -> str:
        return i.get("timestamp") or i.get("created_at") or ""
    secret_incidents.sort(key=_ts, reverse=True)
    recent_secrets = [
        {
            "id":           i.get("id"),
            "secret_type":  i.get("secret_type"),
            "severity":     i.get("severity"),
            "action":       i.get("action"),
            "timestamp":    i.get("timestamp"),
            "user_email":   i.get("user_email"),
            "tab_title":    i.get("tab_title"),
            "tab_url":      i.get("tab_url"),
        }
        for i in secret_incidents[:5]
    ]

    return {
        "error": 0,
        "stats": {
            "total_incidents":    len(incidents),
            "incidents_this_week": len(this_week),
            "total_devices":      len(devices),
            "team_members":       len(members),
            "threats_blocked":    len(blocked),
            "threats_masked":     len(masked),
            "critical_incidents": len(critical),
            "severity_breakdown": dict(severity_counts),
            "action_breakdown":   action_breakdown,
        },
        "recent_secrets": recent_secrets,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/live-threats  —  most recent 50 incidents across all members
# ---------------------------------------------------------------------------

@router.get("/admin/live-threats")
def admin_live_threats(
    limit: int = Query(50, ge=1, le=200),
    user=Depends(verify_supabase_jwt)
):
    ctx = _require_admin(user)

    res = (
        _sb()
        .table("incidents")
        .select("id, user_email, browser_id, tab_url, tab_title, secret_type, severity, action, timestamp, extension_version")
        .eq("org_id", ctx["org_id"])
        .order("timestamp", desc=True)
        .limit(limit)
        .execute()
    )

    return {
        "error": 0,
        "incidents": res.data or [],
        "count": len(res.data or []),
    }


# ---------------------------------------------------------------------------
# GET /api/admin/incidents  —  all incidents with optional filters
# ---------------------------------------------------------------------------

@router.get("/admin/incidents")
def admin_incidents(
    severity: Optional[str] = Query(None),
    secret_type: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    user=Depends(verify_supabase_jwt)
):
    ctx = _require_admin(user)

    query = (
        _sb()
        .table("incidents")
        .select("*")
        .eq("org_id", ctx["org_id"])
        .order("timestamp", desc=True)
    )

    if severity:
        query = query.eq("severity", severity)
    if secret_type:
        query = query.eq("secret_type", secret_type)
    if from_date:
        query = query.gte("timestamp", from_date)
    if to_date:
        query = query.lte("timestamp", to_date)

    res = query.execute()
    incidents = res.data or []

    return {
        "error": 0,
        "incidents": incidents,
        "count": len(incidents),
    }


# ---------------------------------------------------------------------------
# GET /api/admin/incidents/secrets  —  secret detection incidents only
# ---------------------------------------------------------------------------

@router.get("/admin/incidents/secrets")
def admin_incidents_secrets(
    user=Depends(verify_supabase_jwt),
    page: int = Query(0, ge=0),
    page_size: int = Query(200, ge=1, le=500),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    ctx = _require_admin(user)
    try:
        q = (
            _sb()
            .table("incidents")
            .select("*", count="exact")
            .eq("org_id", ctx["org_id"])
            .neq("secret_type", "url_visit")
            .neq("secret_type", "phishing")
            .neq("secret_type", "email_recipient")
            .order("timestamp", desc=True)
        )
        if start_time:
            q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
        if end_time:
            q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
        q = q.range(page * page_size, (page + 1) * page_size - 1)
        res = q.execute()
        incidents = res.data or []
        total = res.count or len(incidents)

        by_type = defaultdict(int)
        by_severity = defaultdict(int)
        for i in incidents:
            by_type[i.get("secret_type", "unknown")] += 1
            by_severity[i.get("severity", "unknown")] += 1

        return {
            "error": 0,
            "incidents": incidents,
            "count": len(incidents),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-total // page_size)),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(exc)})


# ---------------------------------------------------------------------------
# GET /api/admin/incidents/phishing  —  url_visit / phishing type incidents
# ---------------------------------------------------------------------------

@router.get("/admin/incidents/phishing")
def admin_incidents_phishing(
    user=Depends(verify_supabase_jwt),
    page: int = Query(0, ge=0),
    page_size: int = Query(200, ge=1, le=500),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    ctx = _require_admin(user)
    try:
        q = (
            _sb()
            .table("incidents")
            .select("*", count="exact")
            .eq("org_id", ctx["org_id"])
            .in_("secret_type", ["url_visit", "phishing"])
            .order("timestamp", desc=True)
        )
        if start_time:
            q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
        if end_time:
            q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
        q = q.range(page * page_size, (page + 1) * page_size - 1)
        res = q.execute()
        incidents = res.data or []
        total = res.count or len(incidents)

        status_counts = defaultdict(int)
        for i in incidents:
            extra = i.get("extra") or {}
            status_counts[extra.get("site_status", extra.get("status", "unknown"))] += 1

        return {
            "error": 0,
            "incidents": incidents,
            "count": len(incidents),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-total // page_size)),
            "by_status": dict(status_counts),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(exc)})


# ---------------------------------------------------------------------------
# GET /api/admin/team  —  team members with their incident counts
# ---------------------------------------------------------------------------

@router.get("/admin/team")
def admin_team(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    # Get all org members
    members_res = (
        _sb()
        .table("organization_members")
        .select("user_id, role, joined_at")
        .eq("org_id", org_id)
        .execute()
    )
    members = members_res.data or []

    # Get all incidents for org
    incidents = _fetch_org_incidents(org_id)

    # Count incidents per user
    incident_count = defaultdict(int)
    critical_count = defaultdict(int)
    last_seen = {}
    for i in incidents:
        uid = i.get("user_id")
        if uid:
            incident_count[uid] += 1
            if i.get("severity") == "critical":
                critical_count[uid] += 1
            ts = i.get("timestamp")
            if ts and (uid not in last_seen or ts > last_seen[uid]):
                last_seen[uid] = ts

    # Build member list with email from incidents (email not stored in org_members)
    email_map = {}
    for i in incidents:
        uid = i.get("user_id")
        if uid and uid not in email_map:
            email_map[uid] = i.get("user_email")

    team = []
    for m in members:
        uid = m["user_id"]
        team.append({
            "user_id": uid,
            "email": email_map.get(uid),
            "role": m.get("role"),
            "joined_at": m.get("joined_at"),
            "total_incidents": incident_count[uid],
            "critical_incidents": critical_count[uid],
            "last_active": last_seen.get(uid),
        })

    return {
        "error": 0,
        "team": team,
        "total_members": len(team),
    }


# ---------------------------------------------------------------------------
# Admin settings model — matches actual user_settings table columns
# ---------------------------------------------------------------------------

class AdminSettingsUpdate(BaseModel):
    # Dashboard
    show_risk_score: Optional[bool] = None
    show_recent_activity: Optional[bool] = None
    animated_charts: Optional[bool] = None
    auto_refresh: Optional[bool] = None
    # Detection
    enable_detection: Optional[bool] = None
    auto_mask_critical: Optional[bool] = None
    show_notifications: Optional[bool] = None
    mask_console: Optional[bool] = None
    scan_large_docs: Optional[bool] = None
    realtime_updates: Optional[bool] = None
    auto_mask_editor: Optional[bool] = None
    global_masking_status: Optional[bool] = None
    enterprise_data_collection: Optional[bool] = None
    email_dlp_enabled: Optional[bool] = None
    # Masking
    masking_style: Optional[str] = None
    preserve_context: Optional[bool] = None
    auto_mask_textareas: Optional[bool] = None
    auto_mask_inputs: Optional[bool] = None
    # Overlay
    overlay_input: Optional[bool] = None
    overlay_textarea: Optional[bool] = None
    overlay_editor: Optional[bool] = None
    # Network
    block_network_secrets: Optional[bool] = None
    block_form_submission: Optional[bool] = None
    aggressive_email_blocking: Optional[bool] = None
    # Severity / detection levels
    detect_critical: Optional[bool] = None
    detect_high: Optional[bool] = None
    detect_medium: Optional[bool] = None
    detect_low: Optional[bool] = None
    # Notifications
    notify_critical: Optional[bool] = None
    notify_high: Optional[bool] = None
    # Enterprise extras — arrays stored as JSON in Supabase
    site_exclusions_status: Optional[bool] = None
    waf_social_domain: Optional[list] = None
    site_exclusions: Optional[list] = None
    enterprise_email_domains: Optional[list] = None
    Plans: Optional[str] = None


# ---------------------------------------------------------------------------
# GET /api/admin/me  —  current admin's profile (email, name, org, plan)
# ---------------------------------------------------------------------------

@router.get("/admin/me")
def admin_me(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    user_id = ctx["user_id"]

    # Pull email, metadata, and registration date from Supabase auth
    email = ""
    display_name = ""
    registered_at = ""
    try:
        auth_user = _sb().auth.admin.get_user_by_id(user_id)
        if auth_user and auth_user.user:
            email        = auth_user.user.email or ""
            meta         = auth_user.user.user_metadata or {}
            display_name = meta.get("full_name") or meta.get("name") or email.split("@")[0]
            ca           = auth_user.user.created_at
            if ca:
                registered_at = ca.isoformat() if hasattr(ca, "isoformat") else str(ca)
    except Exception:
        pass

    # Pull company_name from organizations table
    company_name = ""
    try:
        org = _sb().table("organizations").select("name").eq("id", ctx["org_id"]).execute()
        if org.data:
            company_name = org.data[0].get("name") or ""
    except Exception:
        pass

    # Pull plan from user_subscriptions
    plan = "enterprise"
    plan_status = "active"
    try:
        sub = _sb().table("user_subscriptions").select("plan_id, status").eq("user_id", user_id).execute()
        if sub.data:
            plan        = sub.data[0].get("plan_id", "enterprise")
            plan_status = sub.data[0].get("status", "active")
    except Exception:
        pass

    return {
        "error": 0,
        "user_id":       user_id,
        "email":         email,
        "display_name":  display_name or "Admin",
        "org_id":        ctx["org_id"],
        "role":          ctx["role"],
        "company_name":  company_name,
        "plan":          plan,
        "plan_status":   plan_status,
        "registered_at": registered_at,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/settings  —  read admin's own row from user_settings
# ---------------------------------------------------------------------------

@router.get("/admin/settings")
def admin_get_settings(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    user_id = ctx["user_id"]

    res = (
        _sb()
        .table("user_settings")
        .select("*")
        .eq("user_id", user_id)
        .execute()
    )

    if not res.data:
        _sb().table("user_settings").insert({"user_id": user_id}).execute()
        res = (
            _sb()
            .table("user_settings")
            .select("*")
            .eq("user_id", user_id)
            .execute()
        )

    return {"error": 0, "settings": res.data[0]}


# ---------------------------------------------------------------------------
# PUT /api/admin/settings  —  update admin's own row in user_settings
# ---------------------------------------------------------------------------

@router.put("/admin/settings")
def admin_update_settings(body: AdminSettingsUpdate, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    user_id = ctx["user_id"]

    updates = {k: v for k, v in body.model_dump().items() if v is not None}

    if not updates:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "No fields provided to update"})

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    _sb().table("user_settings").upsert(
        {"user_id": user_id, **updates}
    ).execute()

    res = (
        _sb()
        .table("user_settings")
        .select("*")
        .eq("user_id", user_id)
        .execute()
    )

    return {"error": 0, "settings": res.data[0]}


# ---------------------------------------------------------------------------
# GET /api/admin/incidents/email-dlp
# ---------------------------------------------------------------------------

@router.get("/admin/incidents/email-dlp")
def admin_incidents_email_dlp(
    user=Depends(verify_supabase_jwt),
    page: int = Query(0, ge=0),
    page_size: int = Query(200, ge=1, le=500),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    ctx = _require_admin(user)
    try:
        q = (
            _sb().table("incidents")
            .select("*", count="exact")
            .eq("org_id", ctx["org_id"])
            .eq("secret_type", "email_recipient")
            .order("timestamp", desc=True)
        )
        if start_time:
            q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
        if end_time:
            q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
        q = q.range(page * page_size, (page + 1) * page_size - 1)
        res = q.execute()
        incidents = res.data or []
        total = res.count or len(incidents)

        by_severity = defaultdict(int)
        by_action = defaultdict(int)
        for i in incidents:
            by_severity[i.get("severity", "unknown")] += 1
            by_action[i.get("action", "unknown")] += 1

        return {
            "error": 0,
            "incidents": incidents,
            "count": len(incidents),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-total // page_size)),
            "by_severity": dict(by_severity),
            "by_action": dict(by_action),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(exc)})


# ---------------------------------------------------------------------------
# GET /api/admin/secret-scanner
# ---------------------------------------------------------------------------

@router.get("/admin/secret-scanner")
def admin_secret_scanner(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    res = (
        _sb().table("incidents").select("*")
        .eq("org_id", ctx["org_id"]).neq("secret_type", "url_visit")
        .neq("secret_type", "phishing")
        .order("timestamp", desc=True).execute()
    )
    incidents = res.data or []
    by_type = defaultdict(int)
    by_severity = defaultdict(int)
    by_user = defaultdict(int)
    by_domain = defaultdict(int)
    by_day = defaultdict(int)
    for i in incidents:
        by_type[i.get("secret_type", "unknown")] += 1
        by_severity[i.get("severity", "unknown")] += 1
        by_user[i.get("user_email", "unknown")] += 1
        try:
            from urllib.parse import urlparse as _up
            d = _up(i.get("tab_url", "")).netloc or i.get("tab_url", "")[:40]
            by_domain[d] += 1
        except Exception:
            pass
        if i.get("timestamp"):
            by_day[i["timestamp"][:10]] += 1
    return {
        "error": 0,
        "total_secrets": len(incidents),
        "by_type": dict(by_type),
        "by_severity": dict(by_severity),
        "top_users": [{"email": e, "count": c} for e, c in sorted(by_user.items(), key=lambda x: x[1], reverse=True)[:5]],
        "top_domains": [{"domain": d, "count": c} for d, c in sorted(by_domain.items(), key=lambda x: x[1], reverse=True)[:5]],
        "daily_trend": [{"date": d, "count": c} for d, c in sorted(by_day.items())[-30:]],
        "recent": incidents[:10],
    }


# ---------------------------------------------------------------------------
# GET /api/admin/browser-protection
# ---------------------------------------------------------------------------

@router.get("/admin/browser-protection")
def admin_browser_protection(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    incidents = _fetch_org_incidents(ctx["org_id"])
    devices_per_user = defaultdict(set)
    extension_versions = defaultdict(int)
    active_browsers = defaultdict(int)
    blocked_count = 0
    now = datetime.now(timezone.utc)
    activity_24h = 0
    activity_7d = 0
    for i in incidents:
        uid = i.get("user_id")
        bid = i.get("browser_id")
        if uid and bid:
            devices_per_user[uid].add(bid)
        if i.get("extension_version"):
            extension_versions[i["extension_version"]] += 1
        if bid:
            active_browsers[bid] += 1
        if i.get("action") in ("blocked", "masked"):
            blocked_count += 1
        ts = i.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt >= now - timedelta(hours=24):
                    activity_24h += 1
                if dt >= now - timedelta(days=7):
                    activity_7d += 1
            except Exception:
                pass
    return {
        "error": 0,
        "stats": {
            "total_devices": sum(len(v) for v in devices_per_user.values()),
            "total_users_with_extension": len(devices_per_user),
            "threats_blocked": blocked_count,
            "activity_last_24h": activity_24h,
            "activity_last_7d": activity_7d,
        },
        "extension_versions": dict(extension_versions),
        "top_browsers": sorted([{"browser_id": b, "count": c} for b, c in active_browsers.items()], key=lambda x: x["count"], reverse=True)[:10],
    }


# ---------------------------------------------------------------------------
# GET /api/admin/phishing-stats
# ---------------------------------------------------------------------------

@router.get("/admin/phishing-stats")
def admin_phishing_stats(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    res = (
        _sb().table("incidents").select("*")
        .eq("org_id", ctx["org_id"]).in_("secret_type", ["url_visit", "phishing"])
        .order("timestamp", desc=True).execute()
    )
    incidents = res.data or []
    now = datetime.now(timezone.utc)
    by_status = defaultdict(int)
    by_hour = defaultdict(int)
    by_day = defaultdict(int)
    by_domain = defaultdict(int)
    users_affected = set()
    blocked_count = 0
    last24h_count = 0
    for i in incidents:
        extra = i.get("extra") or {}
        by_status[extra.get("site_status", extra.get("status", "unknown"))] += 1
        if i.get("action") in ("blocked", "danger"):
            blocked_count += 1
        if i.get("user_id"):
            users_affected.add(i["user_id"])
        ts = i.get("timestamp")
        if ts:
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt >= now - timedelta(hours=24):
                    last24h_count += 1
                    by_hour[dt.strftime("%H:00")] += 1
                by_day[ts[:10]] += 1
            except Exception:
                pass
        try:
            from urllib.parse import urlparse as _up
            d = _up(i.get("tab_url", "")).netloc or i.get("tab_url", "")[:30]
            by_domain[d] += 1
        except Exception:
            pass
    members_res = _sb().table("organization_members").select("user_id").eq("org_id", ctx["org_id"]).execute()
    total_members = len(members_res.data or [])
    pct_protected = round(len(users_affected) / total_members * 100, 1) if total_members else 0
    return {
        "error": 0,
        "kpis": {
            "total_phishing_incidents": len(incidents),
            "blocked_last_24h": last24h_count,
            "threats_blocked": blocked_count,
            "users_affected": len(users_affected),
            "pct_users_protected": pct_protected,
            "total_members": total_members,
        },
        "by_status": dict(by_status),
        "top_domains": sorted([{"domain": d, "count": c} for d, c in by_domain.items()], key=lambda x: x["count"], reverse=True)[:10],
        "hourly_trend_24h": [{"hour": h, "count": c} for h, c in sorted(by_hour.items())],
        "daily_trend": [{"date": d, "count": c} for d, c in sorted(by_day.items())[-30:]],
    }


# ---------------------------------------------------------------------------
# POST /api/admin/members/invite
# ---------------------------------------------------------------------------

class InviteRequest(BaseModel):
    email: str
    role: Optional[str] = "member"


@router.post("/admin/members/invite")
def admin_invite_member(body: InviteRequest, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]
    if body.role not in ("admin", "member"):
        raise HTTPException(status_code=400, detail={"error": 1, "message": "Role must be 'admin' or 'member'"})
    existing_res = _sb().table("incidents").select("user_id, user_email").eq("user_email", body.email).limit(1).execute()
    if existing_res.data:
        invited_user_id = existing_res.data[0]["user_id"]
        already_res = _sb().table("organization_members").select("user_id").eq("org_id", org_id).eq("user_id", invited_user_id).execute()
        if already_res.data:
            raise HTTPException(status_code=409, detail={"error": 1, "message": "User is already a member of this organization"})
        _sb().table("organization_members").insert({"org_id": org_id, "user_id": invited_user_id, "role": body.role, "invited_by": ctx["user_id"]}).execute()
        return {"error": 0, "message": f"{body.email} added to organization as {body.role}", "user_id": invited_user_id, "role": body.role}
    return {"error": 0, "message": f"Invite pending for {body.email}. They will join when they sign up.", "status": "pending", "invited_email": body.email, "role": body.role}


# ---------------------------------------------------------------------------
# DELETE /api/admin/members/{member_user_id}
# ---------------------------------------------------------------------------

@router.delete("/admin/members/{member_user_id}")
def admin_remove_member(member_user_id: str, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]
    if member_user_id == ctx["user_id"]:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "You cannot remove yourself from the organization"})
    existing = _sb().table("organization_members").select("user_id, role").eq("org_id", org_id).eq("user_id", member_user_id).execute()
    if not existing.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Member not found in this organization"})
    if existing.data[0].get("role") == "owner":
        raise HTTPException(status_code=403, detail={"error": 1, "message": "Cannot remove the organization owner"})
    _sb().table("organization_members").delete().eq("org_id", org_id).eq("user_id", member_user_id).execute()
    return {"error": 0, "message": "Member removed from the organization", "removed_user_id": member_user_id}


# ---------------------------------------------------------------------------
# Default integration definitions (seeded on first GET)
# ---------------------------------------------------------------------------

_DEFAULT_INTEGRATIONS = [
    {"integration_id": "github",   "name": "GitHub",     "category": "Source Control",  "status": "disconnected", "webhook_url": "", "scope": "repo, admin:org_hook"},
    {"integration_id": "gitlab",   "name": "GitLab",     "category": "Source Control",  "status": "disconnected", "webhook_url": "", "scope": "read_api, read_repository"},
    {"integration_id": "aws",      "name": "AWS",        "category": "Cloud",           "status": "disconnected", "webhook_url": "", "scope": "ReadOnly + CloudTrail"},
    {"integration_id": "docker",   "name": "Docker",     "category": "Container",       "status": "disconnected", "webhook_url": "", "scope": "pull, manifest"},
    {"integration_id": "slack",    "name": "Slack",      "category": "Communication",   "status": "disconnected", "webhook_url": "", "scope": "channels:history, chat:write"},
    {"integration_id": "k8s",      "name": "Kubernetes", "category": "Orchestration",   "status": "disconnected", "webhook_url": "", "scope": "secrets, configmaps"},
    {"integration_id": "jenkins",  "name": "Jenkins",    "category": "CI/CD",           "status": "disconnected", "webhook_url": "", "scope": "Job/Build read access"},
    {"integration_id": "vercel",   "name": "Vercel",     "category": "Deployment",      "status": "disconnected", "webhook_url": "", "scope": "read:env, read:deployment"},
    {"integration_id": "email",    "name": "Email",      "category": "Reporting",       "status": "disconnected", "webhook_url": "", "scope": "incident reports"},
    {"integration_id": "jira",     "name": "Jira",       "category": "Reporting",       "status": "disconnected", "webhook_url": "", "scope": "create issues"},
]


# ---------------------------------------------------------------------------
# GET /api/admin/integrations  —  list all integrations for the org
# ---------------------------------------------------------------------------

@router.get("/admin/integrations")
def admin_get_integrations(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    res = _sb().table("org_integrations").select("*").eq("org_id", org_id).execute()

    # If org has no integrations yet, seed all 8 defaults
    if not res.data:
        rows = [{"org_id": org_id, **d} for d in _DEFAULT_INTEGRATIONS]
        _sb().table("org_integrations").insert(rows).execute()
        res = _sb().table("org_integrations").select("*").eq("org_id", org_id).execute()

    integrations = res.data or []

    # Summary counts
    connected = sum(1 for i in integrations if i.get("status") == "connected")
    warning = sum(1 for i in integrations if i.get("status") == "warning")
    disconnected = sum(1 for i in integrations if i.get("status") == "disconnected")

    return {
        "error": 0,
        "summary": {
            "total": len(integrations),
            "connected": connected,
            "warning": warning,
            "disconnected": disconnected,
        },
        "integrations": integrations,
    }


# ---------------------------------------------------------------------------
# PUT /api/admin/integrations/{integration_id}  —  update status / config
# ---------------------------------------------------------------------------

class IntegrationUpdate(BaseModel):
    status: Optional[str] = None       # 'connected' | 'warning' | 'disconnected'
    webhook_url: Optional[str] = None
    scope: Optional[str] = None
    config: Optional[dict] = None
    last_sync_at: Optional[str] = None


@router.put("/admin/integrations/{integration_id}")
def admin_update_integration(integration_id: str, body: IntegrationUpdate, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    valid_statuses = ("connected", "warning", "disconnected")
    if body.status and body.status not in valid_statuses:
        raise HTTPException(status_code=400, detail={"error": 1, "message": f"Status must be one of: {', '.join(valid_statuses)}"})

    # Check integration exists for this org
    existing = _sb().table("org_integrations").select("id").eq("org_id", org_id).eq("integration_id", integration_id).execute()
    if not existing.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": f"Integration '{integration_id}' not found"})

    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    _sb().table("org_integrations").update(updates).eq("org_id", org_id).eq("integration_id", integration_id).execute()

    res = _sb().table("org_integrations").select("*").eq("org_id", org_id).eq("integration_id", integration_id).execute()
    return {"error": 0, "integration": res.data[0]}


# ---------------------------------------------------------------------------
# POST /api/admin/integrations/{integration_id}/disconnect  —  quick disconnect
# ---------------------------------------------------------------------------

@router.post("/admin/integrations/{integration_id}/disconnect")
def admin_disconnect_integration(integration_id: str, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    existing = _sb().table("org_integrations").select("id").eq("org_id", org_id).eq("integration_id", integration_id).execute()
    if not existing.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": f"Integration '{integration_id}' not found"})

    _sb().table("org_integrations").update({
        "status": "disconnected",
        "webhook_url": "",
        "config": {},
        "last_sync_at": None,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }).eq("org_id", org_id).eq("integration_id", integration_id).execute()

    return {"error": 0, "message": f"{integration_id} disconnected successfully"}


# ---------------------------------------------------------------------------
# POST /api/admin/report/send
# ---------------------------------------------------------------------------

class ReportRequest(BaseModel):
    channels: Optional[list] = None
    recipient_email: Optional[str] = None
    subject: Optional[str] = None


def _build_report(stats):
    now_str = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    plain = f"""SecureLint Enterprise Incident Report
Generated: {now_str}
Total Incidents : {stats["total_incidents"]}
This Week       : {stats["incidents_this_week"]}
Critical        : {stats["critical_incidents"]}
Threats Blocked : {stats["threats_blocked"]}
Team Members    : {stats["team_members"]}
Devices         : {stats["total_devices"]}
Severity        : {stats.get("severity_breakdown", {})}
"""
    html = f"""<div style="font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:24px;border-radius:12px;max-width:600px">
<h2 style="color:#39d353">SecureLint Enterprise — Incident Report</h2>
<p style="color:#8b949e">{now_str}</p>
<table style="width:100%;border-collapse:collapse">
{"".join(f'<tr><td style="padding:8px;border-bottom:1px solid #21262d;color:#8b949e">{k.replace("_"," ").title()}</td><td style="padding:8px;border-bottom:1px solid #21262d;font-weight:700;color:#39d353">{v}</td></tr>' for k,v in [("Total Incidents",stats["total_incidents"]),("This Week",stats["incidents_this_week"]),("Critical",stats["critical_incidents"]),("Threats Blocked",stats["threats_blocked"]),("Team Members",stats["team_members"]),("Devices",stats["total_devices"])])}
</table></div>"""
    total = stats["total_incidents"]
    week = stats["incidents_this_week"]
    crit = stats["critical_incidents"]
    blocked = stats["threats_blocked"]
    slack_text = f":lock: *SecureLint Incident Report* ({now_str})\nTotal: {total} | This Week: {week} | Critical: {crit} | Blocked: {blocked}"
    return plain, html, slack_text


@router.post("/admin/report/send")
def admin_send_report(body: ReportRequest, user=Depends(verify_supabase_jwt)):
    import httpx, resend as _resend, os as _os
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    incidents = _fetch_org_incidents(org_id)
    members_res = _sb().table("organization_members").select("user_id").eq("org_id", org_id).execute()
    devices = {i["browser_id"] for i in incidents if i.get("browser_id")}
    sev = defaultdict(int)
    now = datetime.now(timezone.utc)
    week_ago = now - timedelta(days=7)
    this_week = [i for i in incidents if i.get("timestamp") and datetime.fromisoformat(i["timestamp"].replace("Z", "+00:00")) >= week_ago]
    for i in incidents:
        sev[i.get("severity", "unknown")] += 1
    stats = {"total_incidents": len(incidents), "incidents_this_week": len(this_week), "total_devices": len(devices), "team_members": len(members_res.data or []), "threats_blocked": len([i for i in incidents if i.get("action") in ("blocked", "masked", "allowed")]), "critical_incidents": len([i for i in incidents if i.get("severity") == "critical"]), "severity_breakdown": dict(sev)}

    plain_text, html_body, slack_text = _build_report(stats)
    channels = body.channels or ["slack", "email", "jira"]
    results = {}

    integ_res = _sb().table("org_integrations").select("*").eq("org_id", org_id).in_("integration_id", ["slack", "email", "jira"]).execute()
    imap = {i["integration_id"]: i for i in (integ_res.data or [])}

    if "slack" in channels:
        sl = imap.get("slack", {})
        wh = sl.get("webhook_url", "")
        if sl.get("status") == "connected" and wh:
            try:
                r = httpx.post(wh, json={"text": slack_text}, timeout=10)
                results["slack"] = {"sent": True, "status_code": r.status_code}
            except Exception as e:
                results["slack"] = {"sent": False, "error": str(e)}
        else:
            results["slack"] = {"sent": False, "reason": "Slack not connected or webhook not set"}

    if "email" in channels:
        key = _os.getenv("RESEND_API_KEY", "")
        em = imap.get("email", {})
        recipient = body.recipient_email or (em.get("config") or {}).get("recipient_email", "")
        subject = body.subject or "SecureLint — Incident Report"
        if key and recipient:
            try:
                _resend.api_key = key
                _resend.Emails.send({"from": "SecureLint <reports@securelint.in>", "to": [recipient], "subject": subject, "html": html_body, "text": plain_text})
                results["email"] = {"sent": True, "recipient": recipient}
            except Exception as e:
                results["email"] = {"sent": False, "error": str(e)}
        else:
            results["email"] = {"sent": False, "reason": "RESEND_API_KEY not set or recipient email missing"}

    if "jira" in channels:
        jr = imap.get("jira", {})
        cfg = jr.get("config") or {}
        jira_url, jira_token, jira_project, jira_email = cfg.get("jira_url",""), cfg.get("api_token",""), cfg.get("project_key",""), cfg.get("email","")
        if jr.get("status") == "connected" and jira_url and jira_token and jira_project:
            try:
                import base64
                creds = base64.b64encode(f"{jira_email}:{jira_token}".encode()).decode()
                r = httpx.post(f"{jira_url}/rest/api/3/issue", headers={"Authorization": f"Basic {creds}", "Content-Type": "application/json"}, json={"fields": {"project": {"key": jira_project}, "summary": f"SecureLint Report {datetime.now(timezone.utc).strftime('%Y-%m-%d')}", "description": {"type": "doc", "version": 1, "content": [{"type": "paragraph", "content": [{"type": "text", "text": plain_text}]}]}, "issuetype": {"name": "Task"}}}, timeout=10)
                results["jira"] = {"sent": True, "issue": r.json().get("key")}
            except Exception as e:
                results["jira"] = {"sent": False, "error": str(e)}
        else:
            results["jira"] = {"sent": False, "reason": "Jira not connected or config incomplete (needs jira_url, api_token, project_key, email)"}

    return {"error": 0, "report_sent": any(v.get("sent") for v in results.values()), "channels": results, "stats_summary": stats}


# ---------------------------------------------------------------------------
# GET /api/admin/charts  —  chart-ready data; optional ?severity_type filter
# severity_type: "secrets" | "phishing" | "email_dlp" (omit = all)
# ---------------------------------------------------------------------------

@router.get("/admin/charts")
def admin_charts(
    severity_type: Optional[str] = Query(None),
    user=Depends(verify_supabase_jwt),
):
    ctx = _require_admin(user)
    try:
        all_incidents = _fetch_org_incidents(ctx["org_id"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(exc)})

    # Apply optional type filter
    PHISHING_TYPES = {"url_visit", "phishing"}
    if severity_type == "phishing":
        incidents = [i for i in all_incidents if i.get("secret_type") in PHISHING_TYPES]
    elif severity_type == "email_dlp":
        incidents = [i for i in all_incidents if i.get("secret_type") == "email_recipient"]
    elif severity_type == "secrets":
        incidents = [i for i in all_incidents if i.get("secret_type") not in PHISHING_TYPES and i.get("secret_type") != "email_recipient"]
    else:
        incidents = all_incidents

    now = datetime.now(timezone.utc)

    def parse_ts(ts):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return None

    DAY_NAMES   = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    _PHISHING = {"url_visit", "phishing"}
    secrets  = [i for i in incidents if i.get("secret_type") not in _PHISHING and i.get("secret_type") != "email_recipient"]
    phishing = [i for i in incidents if i.get("secret_type") in _PHISHING]
    dlp      = [i for i in incidents if i.get("secret_type") == "email_recipient"]

    # ── 1. Dual trend: incidents vs resolved (last 6 months) ─────────────
    dual = {}
    for m_offset in range(5, -1, -1):
        target = (now.replace(day=1) - timedelta(days=m_offset * 30))
        key = MONTH_NAMES[target.month - 1]
        dual[key] = {"m": key, "incidents": 0, "resolved": 0}
    for i in incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            key = MONTH_NAMES[dt.month - 1]
            if key in dual:
                dual[key]["incidents"] += 1
                if i.get("action") in ("masked", "blocked", "allowed"):
                    dual[key]["resolved"] += 1
    dual_trend = list(dual.values())

    # ── 2. Heatmap (4 weeks) ─────────────────────────────────────────────
    four_weeks_ago = now - timedelta(days=28)
    day_counts = defaultdict(int)
    for i in incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt and dt >= four_weeks_ago:
            day_counts[dt.strftime("%Y-%m-%d")] += 1

    heat_cells = []
    for d_offset in range(27, -1, -1):
        day = (now - timedelta(days=d_offset)).strftime("%Y-%m-%d")
        count = day_counts[day]
        color = "#161b22" if count == 0 else "#39d353" if count <= 2 else "#d29922" if count <= 5 else "#f85149" if count <= 10 else "#9e1515"
        heat_cells.append(color)

    # ── 3. Week activity bar ──────────────────────────────────────────────
    dow_counts = defaultdict(int)
    for i in incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            dow_counts[dt.weekday()] += 1
    FILL_COLORS = ["#39d353", "#2dd4bf", "#d29922", "#f85149", "#58a6ff", "#bc8cff", "#39d353"]
    week_activity = [{"n": DAY_NAMES[d], "v": dow_counts[d], "fill": FILL_COLORS[d]} for d in range(7)]

    # ── 4. Incident hub stacked bar by weekday ────────────────────────────
    hub_dow = {d: {"day": DAY_NAMES[d], "secrets": 0, "phishing": 0, "dlp": 0} for d in range(7)}
    for i in incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            st = i.get("secret_type", "")
            d = dt.weekday()
            if st in ("url_visit", "phishing"):
                hub_dow[d]["phishing"] += 1
            elif st == "email_recipient":
                hub_dow[d]["dlp"] += 1
            else:
                hub_dow[d]["secrets"] += 1
    hub_weekly = list(hub_dow.values())

    # ── 5. 6-week incident trend ──────────────────────────────────────────
    week_totals = {f"W{6-w}": {"w": f"W{6-w}", "v": 0} for w in range(5, -1, -1)}
    for i in incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            days_ago = (now - dt).days
            week_num = days_ago // 7
            if week_num < 6:
                label = f"W{6-week_num}"
                if label in week_totals:
                    week_totals[label]["v"] += 1
    six_week_trend = list(week_totals.values())

    # ── 6. Daily counts last 7 days ───────────────────────────────────────
    def daily_7d(items):
        out = {}
        for d in range(6, -1, -1):
            day = (now - timedelta(days=d)).strftime("%Y-%m-%d")
            out[day] = {"day": DAY_NAMES[(now - timedelta(days=d)).weekday()], "count": 0}
        for i in items:
            dt = parse_ts(i.get("timestamp", ""))
            if dt and (now - dt).days < 7:
                key = dt.strftime("%Y-%m-%d")
                if key in out:
                    out[key]["count"] += 1
        return list(out.values())

    secrets_daily  = daily_7d(secrets)
    phishing_daily = daily_7d(phishing)
    dlp_daily      = daily_7d(dlp)

    # ── 7. Secret scanner monthly trend ──────────────────────────────────
    sec_monthly = {}
    for m_off in range(5, -1, -1):
        target = (now.replace(day=1) - timedelta(days=m_off * 30))
        key = MONTH_NAMES[target.month - 1]
        sec_monthly[key] = {"m": key, "v": 0}
    for i in secrets:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            key = MONTH_NAMES[dt.month - 1]
            if key in sec_monthly:
                sec_monthly[key]["v"] += 1
    secret_trend = list(sec_monthly.values())

    risk_monthly = {k: {"m": k, "v": 0} for k in sec_monthly}
    for i in secrets:
        dt = parse_ts(i.get("timestamp", ""))
        if dt and i.get("severity") in ("critical", "high"):
            key = MONTH_NAMES[dt.month - 1]
            if key in risk_monthly:
                risk_monthly[key]["v"] += 1
    risk_trend = list(risk_monthly.values())

    url_counts = defaultdict(int)
    for i in secrets:
        try:
            from urllib.parse import urlparse as _up
            d = _up(i.get("tab_url", "")).netloc or i.get("tab_url", "")[:30]
            url_counts[d] += 1
        except Exception:
            pass
    repo_data = sorted([{"t": u, "v": c} for u, c in url_counts.items()], key=lambda x: x["v"], reverse=True)[:8]

    # ── 8. Phishing 24h volume ────────────────────────────────────────────
    hour_detected = defaultdict(int)
    hour_blocked  = defaultdict(int)
    last_24h = now - timedelta(hours=24)
    for i in phishing:
        dt = parse_ts(i.get("timestamp", ""))
        if dt and dt >= last_24h:
            h = dt.strftime("%H:00")
            hour_detected[h] += 1
            extra = i.get("extra") or {}
            if extra.get("site_status") in ("danger", "suspicious") or i.get("action") == "blocked":
                hour_blocked[h] += 1
    hours_24 = [f"{str(h).zfill(2)}:00" for h in range(24)]
    phishing_volume_24h = [{"t": h, "detected": hour_detected[h], "blocked": hour_blocked[h]} for h in hours_24]

    # ── 9. Weekly phishing trend (url_visit) ─────────────────────────────
    week_phishing = {}
    for d in range(6, -1, -1):
        day = (now - timedelta(days=d))
        week_phishing[day.strftime("%Y-%m-%d")] = {"day": DAY_NAMES[day.weekday()], "emails": 0, "pages": 0}
    for i in phishing:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            key = dt.strftime("%Y-%m-%d")
            if key in week_phishing:
                extra = i.get("extra") or {}
                if extra.get("site_status") in ("danger", "suspicious"):
                    week_phishing[key]["emails"] += 1
                else:
                    week_phishing[key]["pages"] += 1
    weekly_phishing_trend = list(week_phishing.values())

    # ── 10. Attack types donut ────────────────────────────────────────────
    status_counts = defaultdict(int)
    for i in phishing:
        extra = i.get("extra") or {}
        st = extra.get("site_status", extra.get("status", "unknown"))
        status_counts[st] += 1
    total_ph = len(phishing) or 1
    DONUT_COLORS = {"safe": "#39d353", "suspicious": "#d29922", "danger": "#f85149", "unsafe": "#dc2626", "unknown": "#8b949e"}
    attack_types = [{"label": k.title(), "pct": round(v / total_ph * 100, 1), "color": DONUT_COLORS.get(k, "#58a6ff")} for k, v in status_counts.items()]

    # ── 11. Top targeted users (phishing) ────────────────────────────────
    user_phishing = defaultdict(int)
    for i in phishing:
        user_phishing[i.get("user_email", "unknown")] += 1
    top_targeted = sorted([{"name": e, "val": c} for e, c in user_phishing.items()], key=lambda x: x["val"], reverse=True)[:8]

    # ── 12. Email DLP weekly trend ────────────────────────────────────────
    week_dlp = {}
    for d in range(6, -1, -1):
        day = (now - timedelta(days=d))
        week_dlp[day.strftime("%Y-%m-%d")] = {"day": DAY_NAMES[day.weekday()], "count": 0}
    for i in dlp:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            key = dt.strftime("%Y-%m-%d")
            if key in week_dlp:
                week_dlp[key]["count"] += 1
    dlp_weekly_trend = list(week_dlp.values())

    # ── 13. Browser protection charts ────────────────────────────────────
    safe_monthly    = {k: {"t": k, "v": 0} for k in sec_monthly}
    blocked_monthly = {k: {"t": k, "v": 0} for k in sec_monthly}
    for i in all_incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            key = MONTH_NAMES[dt.month - 1]
            if key in safe_monthly:
                if i.get("action") == "allowed":
                    safe_monthly[key]["v"] += 1
                elif i.get("action") in ("blocked", "masked"):
                    blocked_monthly[key]["v"] += 1

    action_counts = defaultdict(int)
    for i in all_incidents:
        action_counts[i.get("action", "unknown")] += 1
    browser_pie = [
        {"name": "Safe",    "value": action_counts.get("allowed",  0), "color": "#39d353"},
        {"name": "Blocked", "value": action_counts.get("blocked",  0), "color": "#f85149"},
        {"name": "Masked",  "value": action_counts.get("masked",   0), "color": "#d29922"},
    ]
    ph_monthly = {k: {"t": k, "v": 0} for k in sec_monthly}
    for i in phishing:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            key = MONTH_NAMES[dt.month - 1]
            if key in ph_monthly:
                ph_monthly[key]["v"] += 1

    # ── 14. Team activity charts ──────────────────────────────────────────
    team_dow = defaultdict(int)
    for i in all_incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            team_dow[dt.weekday()] += 1
    team_activity = [{"d": DAY_NAMES[d], "events": team_dow[d]} for d in range(7)]

    max_inc = max((v["v"] for v in six_week_trend), default=1) or 1
    score_trend = [{"d": f"W{idx+1}", "v": max(50, round(100 - (w["v"] / max_inc * 50)))} for idx, w in enumerate(six_week_trend[-4:])]

    return {
        "error": 0,
        "severity_type": severity_type,
        "threat_analytics": {
            "dual_trend":   dual_trend,
            "heat_cells":   heat_cells,
            "week_activity": week_activity,
        },
        "incident_reports": {
            "hub_weekly":       hub_weekly,
            "six_week_trend":   six_week_trend,
            "secrets_daily_7d": secrets_daily,
            "phishing_daily_7d": phishing_daily,
            "dlp_daily_7d":     dlp_daily,
            "dlp_weekly_trend": dlp_weekly_trend,
        },
        "secret_scanner": {
            "trend_data": secret_trend,
            "risk_data":  risk_trend,
            "repo_data":  repo_data,
        },
        "phishing_monitoring": {
            "volume_24h":    phishing_volume_24h,
            "weekly_trend":  weekly_phishing_trend,
            "attack_types":  attack_types,
            "top_targeted":  top_targeted,
        },
        "browser_protection": {
            "safe_data":         list(safe_monthly.values()),
            "blocked_data":      list(blocked_monthly.values()),
            "pie_data":          browser_pie,
            "phish_trend_data":  list(ph_monthly.values()),
        },
        "team_activity": {
            "activity_data": team_activity,
            "score_trend":   score_trend,
        },
    }
