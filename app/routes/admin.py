from fastapi import APIRouter, Depends, HTTPException, Query
from supabase import create_client
from typing import Any, Dict, List, Optional
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


# ---------------------------------------------------------------------------
# Canonical incident-type groups  (incidents.type column values)
# ---------------------------------------------------------------------------

# Secret / masking types
TYPE_SECRETS: set = {
    "secret_masking",    # secrets typed/pasted in text fields
    "console_masking",   # secrets detected in browser console
    "network_block",     # outbound network request carrying a secret
}

# Phishing sub-categories
TYPE_PHISHING_SITE:  set = {"phishing_site", "url_visit"}
TYPE_PHISHING_WAF:   set = {"waf_domain"}
TYPE_PHISHING_HOVER: set = {"link_hover_phish"}
TYPE_EMAIL_PHISH:    set = {"Gmail_Phish", "outlook_phish",
                             "gmail_phish", "outlook_phish"}   # lower-case aliases
TYPE_ALL_PHISHING:   set = (
    TYPE_PHISHING_SITE | TYPE_PHISHING_WAF |
    TYPE_PHISHING_HOVER | TYPE_EMAIL_PHISH
)

# Email DLP
TYPE_EMAIL_DLP: set = {"email_dlp"}

# Extension events
TYPE_EXTENSION: set = {
    "extension_install", "extension_uninstall", "extension_sync",
    "extension_all", "extension_malicious", "extension_blacklist",
    "blacklist_extensions_visit",
}

# Flat set of every known type → used for validation and filtering
_ALL_KNOWN_TYPES: set = (
    TYPE_SECRETS | TYPE_ALL_PHISHING | TYPE_EMAIL_DLP | TYPE_EXTENSION
)

# Category shortcut keywords accepted by ?severity_type= or ?type=
_CATEGORY_SHORTCUTS: Dict[str, str] = {
    "secrets":   "secrets",
    "phishing":  "phishing",
    "email_dlp": "email_dlp",
    "extension": "extension",
}


def _category(incident: dict) -> str:
    """
    Returns one of: secrets | email_dlp | phishing | extension | other
    based on the incidents.type column (falls back to secret_type for legacy rows).
    """
    t = (incident.get("type") or "").strip()
    t_low = t.lower()
    if t_low in {s.lower() for s in TYPE_SECRETS}:
        return "secrets"
    if t_low in {s.lower() for s in TYPE_EMAIL_DLP}:
        return "email_dlp"
    if t_low in {s.lower() for s in TYPE_ALL_PHISHING}:
        return "phishing"
    if t_low in {s.lower() for s in TYPE_EXTENSION}:
        return "extension"
    # legacy fallback via secret_type
    st = (incident.get("secret_type") or "").lower()
    if st in {"url_visit", "phishing", "phishing_mail"}:
        return "phishing"
    if st in {"email_recipient", "email_dlp"}:
        return "email_dlp"
    if st in {"secret_masking", "console_masking", "network_block"}:
        return "secrets"
    return "other" if not t else t_low


def _resolve_filter(type_val: Optional[str], severity_type_val: Optional[str]):
    """
    Returns (filter_mode, filter_value) where filter_mode is:
      'exact'    → match incidents where type == filter_value (case-insensitive)
      'category' → match incidents where _category(i) == filter_value
      None       → no filter, return all incidents
    """
    # ?type= always means exact match on the type column
    if type_val:
        v = type_val.strip()
        # If it's a category keyword, treat as category filter
        if v.lower() in _CATEGORY_SHORTCUTS:
            return "category", _CATEGORY_SHORTCUTS[v.lower()]
        return "exact", v

    # ?severity_type= accepts either category keywords OR exact type values
    if severity_type_val:
        v = severity_type_val.strip()
        if v.lower() in _CATEGORY_SHORTCUTS:
            return "category", _CATEGORY_SHORTCUTS[v.lower()]
        # treat as an exact type value
        return "exact", v

    return None, None


def _fetch_org_incidents(org_id: str, type_filter: Optional[str] = None) -> list:
    """
    Fetch all incidents for the org, sorted newest first.
    type_filter: exact match on the incidents.type column (optional).
    """
    q = (
        _sb()
        .table("incidents")
        .select("*")
        .eq("org_id", org_id)
        .order("timestamp", desc=True)
    )
    if type_filter:
        q = q.eq("type", type_filter)
    return q.execute().data or []


def _filter_by_type(incidents: list, type_val: Optional[str]) -> list:
    """
    Client-side filter on the type column for already-fetched incident lists.
    Matches case-insensitively. If type_val is None returns the full list.
    """
    if not type_val:
        return incidents
    t = type_val.lower()
    return [i for i in incidents if (i.get("type") or "").lower() == t]


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

    # ── Breakdown by incidents.type column ───────────────────────────────
    type_breakdown: Dict[str, int] = defaultdict(int)
    category_breakdown: Dict[str, int] = defaultdict(int)
    for i in incidents:
        itype = (i.get("type") or "unknown")
        type_breakdown[itype] += 1
        category_breakdown[_category(i)] += 1

    # ── Top-5 most recent secret incidents ────────────────────────────────
    secret_incidents = [i for i in incidents if _category(i) == "secrets"]
    def _ts(i: dict) -> str:
        return i.get("timestamp") or i.get("created_at") or ""
    secret_incidents.sort(key=_ts, reverse=True)
    recent_secrets = [
        {
            "id":            i.get("id"),
            "type":          i.get("type"),
            "secret_type":   i.get("secret_type"),
            "severity":      i.get("severity"),
            "action":        i.get("action"),
            "timestamp":     i.get("timestamp"),
            "user_email":    i.get("user_email"),
            "tab_title":     i.get("tab_title"),
            "tab_url":       i.get("tab_url"),
            "browser_info":  i.get("browser_info"),
        }
        for i in secret_incidents[:5]
    ]

    return {
        "error": 0,
        "stats": {
            "total_incidents":     len(incidents),
            "incidents_this_week": len(this_week),
            "total_devices":       len(devices),
            "team_members":        len(members),
            "threats_blocked":     len(blocked),
            "threats_masked":      len(masked),
            "critical_incidents":  len(critical),
            "severity_breakdown":  dict(severity_counts),
            "action_breakdown":    action_breakdown,
            # granular: exact incidents.type values
            "type_breakdown":      dict(type_breakdown),
            # rolled-up: secrets | phishing | email_dlp | extension | other
            "category_breakdown":  dict(category_breakdown),
        },
        "recent_secrets": recent_secrets,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/live-threats  —  most recent 50 incidents across all members
# ---------------------------------------------------------------------------

@router.get("/admin/live-threats")
def admin_live_threats(
    limit: int = Query(50, ge=1, le=200),
    type: Optional[str] = Query(None),            # filter by incidents.type
    severity_type: Optional[str] = Query(None),   # alias for type
    severity: Optional[str] = Query(None),
    user=Depends(verify_supabase_jwt),
):
    """
    Most recent incidents across all org members.
    ?type= or ?severity_type= (interchangeable):
      secret_masking | console_masking | network_block | email_dlp |
      phishing_site | url_visit | waf_domain | link_hover_phish |
      Gmail_Phish | outlook_phish | extension_install | extension_malicious | …
    ?severity=critical | high | medium | low
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type

    q = (
        _sb()
        .table("incidents")
        .select(
            "id, type, user_email, browser_id, tab_url, tab_title, "
            "secret_type, severity, masked_preview, action, "
            "timestamp, extension_version, browser_info, org_id"
        )
        .eq("org_id", ctx["org_id"])
        .order("timestamp", desc=True)
        .limit(limit)
    )
    if effective_type:
        q = q.eq("type", effective_type)
    if severity:
        q = q.eq("severity", severity)

    rows = q.execute().data or []

    # Attach resolved category to each row
    for r in rows:
        r["category"] = _category(r)

    # Counts per type and category in this result set
    type_counts: Dict[str, int] = defaultdict(int)
    cat_counts:  Dict[str, int] = defaultdict(int)
    for r in rows:
        type_counts[(r.get("type") or "unknown")] += 1
        cat_counts[r["category"]] += 1

    return {
        "error": 0,
        "count": len(rows),
        "type_breakdown": dict(type_counts),
        "category_breakdown": dict(cat_counts),
        "incidents": rows,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/incidents  —  all incidents with optional filters
# ---------------------------------------------------------------------------

@router.get("/admin/incidents")
def admin_incidents(
    type: Optional[str] = Query(None),            # incidents.type column
    severity_type: Optional[str] = Query(None),   # alias for type
    secret_type: Optional[str] = Query(None),     # incidents.secret_type (specific sub-type)
    severity: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    from_date: Optional[str] = Query(None, alias="from"),
    to_date: Optional[str] = Query(None, alias="to"),
    page: int = Query(0, ge=0),
    page_size: int = Query(200, ge=1, le=500),
    user=Depends(verify_supabase_jwt),
):
    """
    All incidents with optional filters.
    ?type= and ?severity_type= are interchangeable:
      secret_masking | console_masking | network_block | email_dlp |
      phishing_site | url_visit | waf_domain | link_hover_phish |
      Gmail_Phish | outlook_phish | extension_install | extension_uninstall |
      extension_sync | extension_all | extension_malicious | extension_blacklist
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type

    query = (
        _sb()
        .table("incidents")
        .select("*", count="exact")
        .eq("org_id", ctx["org_id"])
        .order("timestamp", desc=True)
    )

    if effective_type:
        query = query.eq("type", effective_type)
    if secret_type:
        query = query.eq("secret_type", secret_type)
    if severity:
        query = query.eq("severity", severity)
    if action:
        query = query.eq("action", action)
    if from_date:
        query = query.gte("timestamp", _to_iso(from_date, end_of_day=False))
    if to_date:
        query = query.lte("timestamp", _to_iso(to_date, end_of_day=True))

    query = query.range(page * page_size, (page + 1) * page_size - 1)
    res = query.execute()
    incidents = res.data or []
    total = res.count or len(incidents)

    # Per-result breakdowns
    type_counts: Dict[str, int] = defaultdict(int)
    cat_counts:  Dict[str, int] = defaultdict(int)
    sev_counts:  Dict[str, int] = defaultdict(int)
    for i in incidents:
        type_counts[(i.get("type") or "unknown")] += 1
        cat_counts[_category(i)] += 1
        sev_counts[(i.get("severity") or "unknown")] += 1
        i["category"] = _category(i)

    return {
        "error": 0,
        "count": len(incidents),
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, -(-total // page_size)),
        "type_breakdown": dict(type_counts),
        "category_breakdown": dict(cat_counts),
        "severity_breakdown": dict(sev_counts),
        "incidents": incidents,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/incidents/secrets  —  secret detection incidents only
# ---------------------------------------------------------------------------

@router.get("/admin/incidents/secrets")
def admin_incidents_secrets(
    user=Depends(verify_supabase_jwt),
    page: int = Query(0, ge=0),
    page_size: int = Query(200, ge=1, le=500),
    type: Optional[str] = Query(None),            # narrow to one secret sub-type
    severity_type: Optional[str] = Query(None),   # alias for type
    severity: Optional[str] = Query(None),
    secret_type: Optional[str] = Query(None),     # specific secret_type value
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Secret-masking incidents (secret_masking | console_masking | network_block).
    ?type= or ?severity_type= (interchangeable) to narrow to one sub-type.
    ?secret_type= to filter by a specific secret value (e.g. BASIC_AUTH_URL).
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type
    try:
        # Step 1 – DB: fetch rows whose type is a known secret type OR type is NULL.
        # Legacy rows have type=NULL; client-side step 2 will drop non-secret ones.
        _SECRET_TYPES_CSV = ",".join(sorted(TYPE_SECRETS))
        q = (
            _sb()
            .table("incidents")
            .select("*", count="exact")
            .eq("org_id", ctx["org_id"])
            .or_(f"type.in.({_SECRET_TYPES_CSV}),type.is.null")
            .order("timestamp", desc=True)
        )
        # Narrow to specific secret sub-type if requested
        if effective_type and effective_type.lower() in {s.lower() for s in TYPE_SECRETS}:
            q = q.eq("type", effective_type)
        if severity:
            q = q.eq("severity", severity)
        if secret_type:
            q = q.eq("secret_type", secret_type)
        if start_time:
            q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
        if end_time:
            q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
        q = q.range(page * page_size, (page + 1) * page_size - 1)
        res = q.execute()
        raw = res.data or []
        # Step 2 – client-side: drop legacy NULL-type rows that aren't actually secrets
        incidents = [i for i in raw if _category(i) == "secrets"]
        total = res.count or len(raw)

        by_secret_type: Dict[str, int] = defaultdict(int)
        by_severity:    Dict[str, int] = defaultdict(int)
        by_action:      Dict[str, int] = defaultdict(int)
        for i in incidents:
            by_secret_type[(i.get("secret_type") or "unknown")] += 1
            by_severity[(i.get("severity") or "unknown")] += 1
            by_action[(i.get("action") or "unknown")] += 1

        return {
            "error": 0,
            "count": len(incidents),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-total // page_size)),
            "by_secret_type": dict(by_secret_type),
            "by_severity":    dict(by_severity),
            "by_action":      dict(by_action),
            "incidents": incidents,
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
    type: Optional[str] = Query(None),            # narrow to a specific phishing sub-type
    severity_type: Optional[str] = Query(None),   # alias for type
    severity: Optional[str] = Query(None),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    All phishing-category incidents.
    Covers: phishing_site, url_visit, waf_domain, link_hover_phish,
            Gmail_Phish (secret_type=phishing_mail), outlook_phish.
    ?type= or ?severity_type= (interchangeable) to narrow to a specific sub-type.
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type
    try:
        # Backward-compat: new rows use the type column;
        # legacy rows have secret_type in (url_visit, phishing, phishing_mail) with type=NULL.
        _ALL_PH_CSV = ",".join(sorted(TYPE_ALL_PHISHING))
        _LEGACY_PH_OR = (
            f"type.in.({_ALL_PH_CSV}),"
            "secret_type.in.(url_visit,phishing,phishing_mail)"
        )
        q = (
            _sb()
            .table("incidents")
            .select("*", count="exact")
            .eq("org_id", ctx["org_id"])
            .order("timestamp", desc=True)
        )
        if effective_type:
            q = q.or_(f"type.eq.{effective_type},and(type.is.null,secret_type.eq.{effective_type})")
        else:
            q = q.or_(_LEGACY_PH_OR)
        if severity:
            q = q.eq("severity", severity)
        if start_time:
            q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
        if end_time:
            q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
        q = q.range(page * page_size, (page + 1) * page_size - 1)
        res = q.execute()
        incidents = res.data or []
        total = res.count or len(incidents)

        by_type:   Dict[str, int] = defaultdict(int)
        by_status: Dict[str, int] = defaultdict(int)
        by_sev:    Dict[str, int] = defaultdict(int)
        for i in incidents:
            by_type[(i.get("type") or "unknown")] += 1
            by_sev[(i.get("severity") or "unknown")] += 1
            extra = i.get("extra") or {}
            by_status[extra.get("site_status", extra.get("status", "unknown"))] += 1

        return {
            "error": 0,
            "count": len(incidents),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-total // page_size)),
            "by_type":     dict(by_type),
            "by_status":   dict(by_status),
            "by_severity": dict(by_sev),
            "incidents": incidents,
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
    # Phishing site detection
    phish_detection: Optional[bool] = None
    link_hover_detection: Optional[bool] = None
    phish_detection_alert: Optional[bool] = None
    phish_detection_block: Optional[bool] = None
    domain_age_alert: Optional[bool] = None
    # Phishing mail detection
    phish_mail_detection: Optional[bool] = None
    phish_mail_action: Optional[str] = None
    # Email DLP
    email_dlp_domain: Optional[list] = None
    email_dlp_action: Optional[str] = None
    IT_mail: Optional[str] = None
    # Extension controls
    blacklist_extension: Optional[dict] = None
    blacklist_extension_status: Optional[str] = None
    extension_scrape_data: Optional[bool] = None
    password_breach_data: Optional[bool] = None
    # Misc
    blur_web: Optional[bool] = None


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
    severity: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Email DLP incidents only (type = 'email_dlp').
    These have secret_type = 'email_recipient' on older rows —
    both are matched via the type column going forward.
    """
    ctx = _require_admin(user)
    try:
        # Backward-compat OR:
        #   new rows:    type = 'email_dlp'
        #   legacy rows: secret_type = 'email_dlp' OR 'email_recipient' (older convention)
        q = (
            _sb().table("incidents")
            .select("*", count="exact")
            .eq("org_id", ctx["org_id"])
            .or_("type.eq.email_dlp,secret_type.eq.email_dlp,secret_type.eq.email_recipient")
            .order("timestamp", desc=True)
        )
        if severity:
            q = q.eq("severity", severity)
        if action:
            q = q.eq("action", action)
        if start_time:
            q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
        if end_time:
            q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
        q = q.range(page * page_size, (page + 1) * page_size - 1)
        res = q.execute()
        incidents = res.data or []
        total = res.count or len(incidents)

        by_severity: Dict[str, int] = defaultdict(int)
        by_action:   Dict[str, int] = defaultdict(int)
        recipient_domains: Dict[str, int] = defaultdict(int)
        for i in incidents:
            by_severity[(i.get("severity") or "unknown")] += 1
            by_action[(i.get("action") or "unknown")] += 1
            for rd in (i.get("recipientDomains") or []):
                d = rd.get("domain") if isinstance(rd, dict) else str(rd)
                if d:
                    recipient_domains[d] += 1

        top_domains = sorted(
            [{"domain": d, "count": c} for d, c in recipient_domains.items()],
            key=lambda x: x["count"], reverse=True
        )[:10]

        return {
            "error": 0,
            "count": len(incidents),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-total // page_size)),
            "by_severity":   dict(by_severity),
            "by_action":     dict(by_action),
            "top_recipient_domains": top_domains,
            "incidents": incidents,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(exc)})


# ---------------------------------------------------------------------------
# GET /api/admin/secret-scanner
# ---------------------------------------------------------------------------

@router.get("/admin/secret-scanner")
def admin_secret_scanner(
    user=Depends(verify_supabase_jwt),
    type: Optional[str] = Query(None),            # narrow to secret sub-type (e.g. secret_masking)
    severity_type: Optional[str] = Query(None),   # alias for type
    secret_type: Optional[str] = Query(None),     # specific secret_type value (e.g. BASIC_AUTH_URL)
    severity: Optional[str] = Query(None),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Secret-masking incidents (secret_masking | console_masking | network_block) with analytics.
    ?type= or ?severity_type= — interchangeable (e.g. secret_masking, console_masking)
    ?secret_type=BASIC_AUTH_URL | AWS_KEY | … to drill into a specific secret sub-type.
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type  # both params are interchangeable

    # Step 1 – DB query: pull rows whose type is a known secret type OR type is NULL
    # (legacy rows have type=NULL; we'll exclude non-secrets client-side in step 2).
    _SECRET_TYPES_CSV = ",".join(sorted(TYPE_SECRETS))
    q = (
        _sb().table("incidents").select("*")
        .eq("org_id", ctx["org_id"])
        .or_(f"type.in.({_SECRET_TYPES_CSV}),type.is.null")
        .order("timestamp", desc=True)
    )
    # Narrow to one specific secret sub-type if requested
    if effective_type and effective_type.lower() in {s.lower() for s in TYPE_SECRETS}:
        q = q.eq("type", effective_type)
    if secret_type:
        q = q.eq("secret_type", secret_type)
    if severity:
        q = q.eq("severity", severity)
    if start_time:
        q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
    if end_time:
        q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))

    raw = q.execute().data or []

    # Step 2 – client-side: keep only rows that resolve to the "secrets" category
    # (this drops legacy rows whose type=NULL but secret_type is phishing/dlp).
    incidents = [i for i in raw if _category(i) == "secrets"]

    by_secret_type: Dict[str, int] = defaultdict(int)
    by_severity:    Dict[str, int] = defaultdict(int)
    by_action:      Dict[str, int] = defaultdict(int)
    by_user:        Dict[str, int] = defaultdict(int)
    by_domain:      Dict[str, int] = defaultdict(int)
    by_day:         Dict[str, int] = defaultdict(int)
    for i in incidents:
        by_secret_type[(i.get("secret_type") or "unknown")] += 1
        by_severity[(i.get("severity") or "unknown")] += 1
        by_action[(i.get("action") or "unknown")] += 1
        by_user[(i.get("user_email") or "unknown")] += 1
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
        "by_secret_type": dict(by_secret_type),
        "by_severity":    dict(by_severity),
        "by_action":      dict(by_action),
        "top_users":    [{"email": e, "count": c} for e, c in
                          sorted(by_user.items(),   key=lambda x: x[1], reverse=True)[:10]],
        "top_domains":  [{"domain": d, "count": c} for d, c in
                          sorted(by_domain.items(), key=lambda x: x[1], reverse=True)[:10]],
        "daily_trend":  [{"date": d, "count": c} for d, c in sorted(by_day.items())[-30:]],
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
def admin_phishing_stats(
    user=Depends(verify_supabase_jwt),
    type: Optional[str] = Query(None),            # narrow to one phishing sub-type
    severity_type: Optional[str] = Query(None),   # alias for type
):
    """
    Phishing analytics across all phishing-category types:
      phishing_site | url_visit | waf_domain | link_hover_phish |
      Gmail_Phish | outlook_phish
    ?type= or ?severity_type= (interchangeable) to narrow to a specific sub-type.
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type

    # Backward-compat OR: new rows use the type column;
    # legacy phishing rows have secret_type in (url_visit, phishing, phishing_mail) with type=NULL.
    _ALL_PH_CSV = ",".join(sorted(TYPE_ALL_PHISHING))
    _LEGACY_PH_OR = (
        f"type.in.({_ALL_PH_CSV}),"
        "secret_type.in.(url_visit,phishing,phishing_mail)"
    )
    q = (
        _sb().table("incidents").select("*")
        .eq("org_id", ctx["org_id"])
        .order("timestamp", desc=True)
    )
    if effective_type:
        q = q.or_(f"type.eq.{effective_type},and(type.is.null,secret_type.eq.{effective_type})")
    else:
        q = q.or_(_LEGACY_PH_OR)

    incidents = q.execute().data or []
    now = datetime.now(timezone.utc)

    by_type:   Dict[str, int] = defaultdict(int)
    by_status: Dict[str, int] = defaultdict(int)
    by_hour:   Dict[str, int] = defaultdict(int)
    by_day:    Dict[str, int] = defaultdict(int)
    by_domain: Dict[str, int] = defaultdict(int)
    users_affected: set = set()
    blocked_count = 0
    last24h_count = 0

    for i in incidents:
        by_type[(i.get("type") or "unknown")] += 1
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
            "blocked_last_24h":  last24h_count,
            "threats_blocked":   blocked_count,
            "users_affected":    len(users_affected),
            "pct_users_protected": pct_protected,
            "total_members":     total_members,
        },
        "by_type":   dict(by_type),
        "by_status": dict(by_status),
        "top_domains": sorted(
            [{"domain": d, "count": c} for d, c in by_domain.items()],
            key=lambda x: x["count"], reverse=True
        )[:10],
        "hourly_trend_24h": [{"hour": h, "count": c} for h, c in sorted(by_hour.items())],
        "daily_trend":      [{"date": d, "count": c} for d, c in sorted(by_day.items())[-30:]],
    }


# ---------------------------------------------------------------------------
# GET /api/admin/incidents/extension  —  paginated extension event incidents
# ---------------------------------------------------------------------------

@router.get("/admin/incidents/extension")
def admin_incidents_extension(
    user=Depends(verify_supabase_jwt),
    page: int = Query(0, ge=0),
    page_size: int = Query(200, ge=1, le=500),
    type: Optional[str] = Query(None),            # narrow to one extension sub-type
    severity_type: Optional[str] = Query(None),   # alias for type
    severity: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Extension-related incidents for the org.

    type / severity_type (interchangeable) — omit for all extension events:
      extension_install | extension_uninstall | extension_sync |
      extension_all | extension_malicious | extension_blacklist
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type

    try:
        _EXT_TYPES_CSV = ",".join(sorted(TYPE_EXTENSION))
        q = (
            _sb().table("incidents")
            .select("*", count="exact")
            .eq("org_id", ctx["org_id"])
            .in_("type", list(TYPE_EXTENSION))
            .order("timestamp", desc=True)
        )
        if effective_type:
            q = q.eq("type", effective_type)
        if severity:
            q = q.eq("severity", severity)
        if action:
            q = q.eq("action", action)
        if start_time:
            q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
        if end_time:
            q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
        q = q.range(page * page_size, (page + 1) * page_size - 1)
        res = q.execute()
        incidents = res.data or []
        total = res.count or len(incidents)

        by_type:    Dict[str, int] = defaultdict(int)
        by_severity: Dict[str, int] = defaultdict(int)
        by_action:  Dict[str, int] = defaultdict(int)
        by_user:    Dict[str, int] = defaultdict(int)
        for i in incidents:
            by_type[(i.get("type") or "unknown")] += 1
            by_severity[(i.get("severity") or "unknown")] += 1
            by_action[(i.get("action") or "unknown")] += 1
            by_user[(i.get("user_email") or "unknown")] += 1

        top_users = sorted(
            [{"email": e, "count": c} for e, c in by_user.items()],
            key=lambda x: x["count"], reverse=True
        )[:10]

        return {
            "error": 0,
            "count": len(incidents),
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, -(-total // page_size)),
            "by_type":     dict(by_type),
            "by_severity": dict(by_severity),
            "by_action":   dict(by_action),
            "top_users":   top_users,
            "incidents":   incidents,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(exc)})


# ---------------------------------------------------------------------------
# GET /api/admin/extension-stats  —  analytics summary for extension events
# ---------------------------------------------------------------------------

@router.get("/admin/extension-stats")
def admin_extension_stats(
    user=Depends(verify_supabase_jwt),
    type: Optional[str] = Query(None),            # narrow to one sub-type
    severity_type: Optional[str] = Query(None),   # alias for type
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
):
    """
    Analytics summary for all extension-category incidents.
    ?type= or ?severity_type= (interchangeable) to narrow to a specific sub-type:
      extension_install | extension_uninstall | extension_sync |
      extension_all | extension_malicious | extension_blacklist
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type

    q = (
        _sb().table("incidents").select("*")
        .eq("org_id", ctx["org_id"])
        .in_("type", list(TYPE_EXTENSION))
        .order("timestamp", desc=True)
    )
    if effective_type:
        q = q.eq("type", effective_type)
    if start_time:
        q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
    if end_time:
        q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))

    incidents = q.execute().data or []
    now = datetime.now(timezone.utc)

    by_type:      Dict[str, int] = defaultdict(int)
    by_severity:  Dict[str, int] = defaultdict(int)
    by_action:    Dict[str, int] = defaultdict(int)
    by_user:      Dict[str, int] = defaultdict(int)
    by_day:       Dict[str, int] = defaultdict(int)
    by_hour:      Dict[str, int] = defaultdict(int)
    malicious_count = 0
    blacklisted_count = 0
    last24h_count = 0
    users_affected: set = set()

    for i in incidents:
        t = (i.get("type") or "unknown")
        by_type[t] += 1
        by_severity[(i.get("severity") or "unknown")] += 1
        by_action[(i.get("action") or "unknown")] += 1
        by_user[(i.get("user_email") or "unknown")] += 1
        if t == "extension_malicious":
            malicious_count += 1
        if t == "extension_blacklist":
            blacklisted_count += 1
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

    # Extension details from the extensions JSONB column
    by_extension: Dict[str, int] = defaultdict(int)
    for i in incidents:
        ext = i.get("extensions")
        if isinstance(ext, list):
            for e in ext:
                name = e.get("name") or e.get("id") or "unknown"
                by_extension[name] += 1
        elif isinstance(ext, dict):
            name = ext.get("name") or ext.get("id") or "unknown"
            by_extension[name] += 1

    top_extensions = sorted(
        [{"extension": k, "count": v} for k, v in by_extension.items()],
        key=lambda x: x["count"], reverse=True
    )[:10]
    top_users = sorted(
        [{"email": e, "count": c} for e, c in by_user.items()],
        key=lambda x: x["count"], reverse=True
    )[:10]

    return {
        "error": 0,
        "kpis": {
            "total_extension_events": len(incidents),
            "malicious_detected":     malicious_count,
            "blacklisted_detected":   blacklisted_count,
            "events_last_24h":        last24h_count,
            "users_affected":         len(users_affected),
        },
        "by_type":         dict(by_type),
        "by_severity":     dict(by_severity),
        "by_action":       dict(by_action),
        "top_extensions":  top_extensions,
        "top_users":       top_users,
        "hourly_trend_24h": [{"hour": h, "count": c} for h, c in sorted(by_hour.items())],
        "daily_trend":      [{"date": d, "count": c} for d, c in sorted(by_day.items())[-30:]],
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
# GET /api/admin/org/users  —  all users in the org with profile + stats
# ---------------------------------------------------------------------------

@router.get("/admin/org/users")
def admin_org_users(user=Depends(verify_supabase_jwt)):
    """
    Returns every member of the caller's org with:
      - basic profile (email, display_name, role, joined_at)
      - incident stats (total, critical, last_active)
      - active plan info
    """
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    # 1. All org members
    members_res = (
        _sb().table("organization_members")
        .select("user_id, role, joined_at")
        .eq("org_id", org_id)
        .execute()
    )
    members = members_res.data or []
    member_ids = [m["user_id"] for m in members]

    # 2. All incidents for org — used to derive email + activity stats
    incidents = _fetch_org_incidents(org_id)

    # Build per-user maps from incidents
    email_map: Dict[str, str] = {}
    inc_count: Dict[str, int] = defaultdict(int)
    crit_count: Dict[str, int] = defaultdict(int)
    last_seen: Dict[str, str] = {}
    type_map: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for i in incidents:
        uid = i.get("user_id")
        if not uid:
            continue
        email_map.setdefault(uid, i.get("user_email", ""))
        inc_count[uid] += 1
        if i.get("severity") == "critical":
            crit_count[uid] += 1
        ts = i.get("timestamp") or i.get("created_at") or ""
        if ts and (uid not in last_seen or ts > last_seen[uid]):
            last_seen[uid] = ts
        itype = i.get("type") or i.get("secret_type") or "unknown"
        type_map[uid][itype] += 1

    # 3. Subscription plan per user (batch fetch by user_ids)
    plan_map: Dict[str, str] = {}
    plan_status_map: Dict[str, str] = {}
    if member_ids:
        sub_res = (
            _sb().table("user_subscriptions")
            .select("user_id, plan_id, status")
            .in_("user_id", member_ids)
            .execute()
        )
        for s in (sub_res.data or []):
            plan_map[s["user_id"]] = s.get("plan_id", "pro")
            plan_status_map[s["user_id"]] = s.get("status", "inactive")

    # 4. Build response rows
    team: List[Dict[str, Any]] = []
    for m in members:
        uid = m["user_id"]
        team.append({
            "user_id":            uid,
            "email":              email_map.get(uid, ""),
            "role":               m.get("role"),
            "joined_at":          m.get("joined_at"),
            "plan":               plan_map.get(uid, "pro"),
            "plan_status":        plan_status_map.get(uid, "inactive"),
            "total_incidents":    inc_count[uid],
            "critical_incidents": crit_count[uid],
            "last_active":        last_seen.get(uid),
            "incidents_by_type":  dict(type_map[uid]),
        })

    # Sort: most active first
    team.sort(key=lambda x: x["total_incidents"], reverse=True)

    return {
        "error": 0,
        "org_id": org_id,
        "total_members": len(team),
        "users": team,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/org/settings  —  user_settings for every user in the org
# ---------------------------------------------------------------------------

@router.get("/admin/org/settings")
def admin_org_get_settings(
    user_id_filter: Optional[str] = Query(None, alias="user_id"),
    user=Depends(verify_supabase_jwt),
):
    """
    Returns user_settings rows for all members of the org.
    ?user_id=<uuid>  →  single user's settings only
    """
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    # Resolve org member user_ids
    members_res = (
        _sb().table("organization_members")
        .select("user_id")
        .eq("org_id", org_id)
        .execute()
    )
    member_ids = [m["user_id"] for m in (members_res.data or [])]

    if not member_ids:
        return {"error": 0, "org_id": org_id, "count": 0, "settings": []}

    # Optionally filter to a single member
    if user_id_filter:
        if user_id_filter not in member_ids:
            raise HTTPException(
                status_code=404,
                detail={"error": 1, "message": "User not found in this organization"},
            )
        target_ids = [user_id_filter]
    else:
        target_ids = member_ids

    settings_res = (
        _sb().table("user_settings")
        .select("*")
        .in_("user_id", target_ids)
        .execute()
    )
    settings_rows = settings_res.data or []

    # Build email lookup from incidents for display
    incidents_res = (
        _sb().table("incidents")
        .select("user_id, user_email")
        .eq("org_id", org_id)
        .limit(500)
        .execute()
    )
    email_map: Dict[str, str] = {}
    for i in (incidents_res.data or []):
        email_map.setdefault(i["user_id"], i.get("user_email", ""))

    # Attach email to each settings row for readability
    for row in settings_rows:
        row["user_email"] = email_map.get(row.get("user_id", ""), "")

    return {
        "error": 0,
        "org_id": org_id,
        "count": len(settings_rows),
        "settings": settings_rows,
    }


# ---------------------------------------------------------------------------
# PUT /api/admin/org/settings  —  bulk-update settings for the entire org
# ---------------------------------------------------------------------------

class OrgSettingsBulkUpdate(BaseModel):
    """
    Pass any subset of user_settings fields to update.
    Omit a field to leave it unchanged.
    Optional ?user_id query param targets a single member; omit to update all.
    """
    show_risk_score: Optional[bool] = None
    show_recent_activity: Optional[bool] = None
    animated_charts: Optional[bool] = None
    auto_refresh: Optional[bool] = None
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
    masking_style: Optional[str] = None
    preserve_context: Optional[bool] = None
    auto_mask_textareas: Optional[bool] = None
    auto_mask_inputs: Optional[bool] = None
    overlay_input: Optional[bool] = None
    overlay_textarea: Optional[bool] = None
    overlay_editor: Optional[bool] = None
    block_network_secrets: Optional[bool] = None
    block_form_submission: Optional[bool] = None
    aggressive_email_blocking: Optional[bool] = None
    detect_critical: Optional[bool] = None
    detect_high: Optional[bool] = None
    detect_medium: Optional[bool] = None
    detect_low: Optional[bool] = None
    notify_critical: Optional[bool] = None
    notify_high: Optional[bool] = None
    site_exclusions_status: Optional[bool] = None
    phish_detection: Optional[bool] = None
    link_hover_detection: Optional[bool] = None
    phish_detection_alert: Optional[bool] = None
    phish_detection_block: Optional[bool] = None
    domain_age_alert: Optional[bool] = None
    password_breach_data: Optional[bool] = None
    extension_scrape_data: Optional[bool] = None
    waf_social_domain: Optional[list] = None
    site_exclusions: Optional[list] = None
    enterprise_email_domains: Optional[list] = None
    email_dlp_domain: Optional[list] = None
    email_dlp_action: Optional[str] = None
    IT_mail: Optional[str] = None


@router.put("/admin/org/settings")
def admin_org_update_settings(
    body: OrgSettingsBulkUpdate,
    user_id_filter: Optional[str] = Query(None, alias="user_id"),
    user=Depends(verify_supabase_jwt),
):
    """
    Bulk-update user_settings for every member of the org.
    ?user_id=<uuid>  →  update only that member.
    Only non-null fields from the request body are applied.
    Returns a summary of how many rows were updated.
    """
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": "No fields provided to update"},
        )

    # Resolve members
    members_res = (
        _sb().table("organization_members")
        .select("user_id")
        .eq("org_id", org_id)
        .execute()
    )
    member_ids = [m["user_id"] for m in (members_res.data or [])]

    if not member_ids:
        return {"error": 0, "updated": 0, "message": "No members in organization"}

    if user_id_filter:
        if user_id_filter not in member_ids:
            raise HTTPException(
                status_code=404,
                detail={"error": 1, "message": "User not found in this organization"},
            )
        target_ids = [user_id_filter]
    else:
        target_ids = member_ids

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()

    updated = 0
    errors: List[str] = []
    for uid in target_ids:
        try:
            _sb().table("user_settings").upsert(
                {"user_id": uid, **updates}, on_conflict="user_id"
            ).execute()
            updated += 1
        except Exception as exc:
            errors.append(f"{uid}: {exc}")

    return {
        "error": 0 if not errors else 1,
        "org_id": org_id,
        "targeted": len(target_ids),
        "updated": updated,
        "fields_updated": list(updates.keys()),
        "errors": errors or None,
    }


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
# GET /api/admin/charts  —  chart-ready data
#
# Both params do the same job — use either:
#   ?type=<value>           exact type value:  secret_masking | console_masking |
#                           network_block | email_dlp | phishing_site | url_visit |
#                           waf_domain | link_hover_phish | Gmail_Phish |
#                           outlook_phish | extension_install | extension_uninstall |
#                           extension_sync | extension_all | extension_malicious |
#                           extension_blacklist
#                           OR a category shortcut: secrets | phishing | email_dlp | extension
#
#   ?severity_type=<value>  same values accepted — kept for backward compatibility
# ---------------------------------------------------------------------------

@router.get("/admin/charts")
def admin_charts(
    type: Optional[str] = Query(None),            # exact type OR category keyword
    severity_type: Optional[str] = Query(None),   # same — kept for backward compat
    user=Depends(verify_supabase_jwt),
):
    ctx = _require_admin(user)
    try:
        all_incidents = _fetch_org_incidents(ctx["org_id"])
    except Exception as exc:
        raise HTTPException(status_code=500, detail={"error": 1, "message": str(exc)})

    filter_mode, filter_value = _resolve_filter(type, severity_type)

    if filter_mode == "exact":
        incidents = [i for i in all_incidents
                     if (i.get("type") or "").lower() == filter_value.lower()]
    elif filter_mode == "category":
        incidents = [i for i in all_incidents if _category(i) == filter_value]
    else:
        incidents = all_incidents

    # ── Breakdowns over ALL incidents (not filtered) ─────────────────────
    type_breakdown:     Dict[str, int] = defaultdict(int)
    category_breakdown: Dict[str, int] = defaultdict(int)
    for i in all_incidents:
        type_breakdown[(i.get("type") or "unknown")] += 1
        category_breakdown[_category(i)] += 1

    now = datetime.now(timezone.utc)

    def parse_ts(ts):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return None

    DAY_NAMES   = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

    secrets   = [i for i in incidents if _category(i) == "secrets"]
    phishing  = [i for i in incidents if _category(i) == "phishing"]
    dlp       = [i for i in incidents if _category(i) == "email_dlp"]
    extension = [i for i in incidents if _category(i) == "extension"]

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
    hub_dow = {d: {"day": DAY_NAMES[d], "secrets": 0, "phishing": 0,
                   "dlp": 0, "extension": 0, "other": 0} for d in range(7)}
    for i in incidents:
        dt = parse_ts(i.get("timestamp", ""))
        if dt:
            cat = _category(i)
            d = dt.weekday()
            if cat == "secrets":
                hub_dow[d]["secrets"] += 1
            elif cat == "phishing":
                hub_dow[d]["phishing"] += 1
            elif cat == "email_dlp":
                hub_dow[d]["dlp"] += 1
            elif cat == "extension":
                hub_dow[d]["extension"] += 1
            else:
                hub_dow[d]["other"] += 1
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

    secrets_daily   = daily_7d(secrets)
    phishing_daily  = daily_7d(phishing)
    dlp_daily       = daily_7d(dlp)
    extension_daily = daily_7d(extension)

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
        "active_filter": {
            "type":          type,
            "severity_type": severity_type,
            "resolved_mode":  filter_mode,    # "exact" | "category" | null
            "resolved_value": filter_value,   # e.g. "Gmail_Phish" | "phishing"
        },
        # granular: exact incidents.type values (always all incidents)
        "type_breakdown":     dict(type_breakdown),
        # rolled-up: secrets | phishing | email_dlp | extension | other
        "category_breakdown": dict(category_breakdown),
        "threat_analytics": {
            "dual_trend":    dual_trend,
            "heat_cells":    heat_cells,
            "week_activity": week_activity,
        },
        "incident_reports": {
            "hub_weekly":           hub_weekly,
            "six_week_trend":       six_week_trend,
            "secrets_daily_7d":     secrets_daily,
            "phishing_daily_7d":    phishing_daily,
            "dlp_daily_7d":         dlp_daily,
            "extension_daily_7d":   extension_daily,
            "dlp_weekly_trend":     dlp_weekly_trend,
        },
        "secret_scanner": {
            "trend_data": secret_trend,
            "risk_data":  risk_trend,
            "repo_data":  repo_data,
        },
        "phishing_monitoring": {
            "volume_24h":   phishing_volume_24h,
            "weekly_trend": weekly_phishing_trend,
            "attack_types": attack_types,
            "top_targeted": top_targeted,
        },
        "browser_protection": {
            "safe_data":        list(safe_monthly.values()),
            "blocked_data":     list(blocked_monthly.values()),
            "pie_data":         browser_pie,
            "phish_trend_data": list(ph_monthly.values()),
        },
        "team_activity": {
            "activity_data": team_activity,
            "score_trend":   score_trend,
        },
    }


# ===========================================================================
# RISK & THREAT INTELLIGENCE
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /api/admin/risk-score  —  org-level risk score (0–100)
# ---------------------------------------------------------------------------

def _compute_risk_score(incidents: list, total_members: int) -> dict:
    """
    Heuristic risk score (0-100).
    Higher score = higher risk.
    Factors: severity mix, unblocked critical/high, phishing rate, malicious extensions.
    """
    if not incidents:
        return {"score": 0, "grade": "A", "factors": []}

    total = len(incidents)
    critical = sum(1 for i in incidents if i.get("severity") == "critical")
    high     = sum(1 for i in incidents if i.get("severity") == "high")
    blocked  = sum(1 for i in incidents if i.get("action") in ("blocked", "masked"))
    unblocked_serious = sum(
        1 for i in incidents
        if i.get("severity") in ("critical", "high") and i.get("action") not in ("blocked", "masked")
    )
    phishing_count  = sum(1 for i in incidents if _category(i) == "phishing")
    malicious_count = sum(1 for i in incidents if i.get("type") == "extension_malicious")
    dlp_count       = sum(1 for i in incidents if _category(i) == "email_dlp")

    score = 0
    factors = []

    # Severity weight (max 40 pts)
    sev_score = min(40, round((critical * 4 + high * 2) / max(total, 1) * 40))
    if sev_score > 0:
        score += sev_score
        factors.append({"factor": "High/Critical severity incidents", "contribution": sev_score})

    # Unblocked serious incidents (max 25 pts)
    unblock_score = min(25, round(unblocked_serious / max(total, 1) * 25 * 2))
    if unblock_score > 0:
        score += unblock_score
        factors.append({"factor": "Unblocked critical/high incidents", "contribution": unblock_score})

    # Phishing exposure (max 15 pts)
    ph_score = min(15, round(phishing_count / max(total, 1) * 15))
    if ph_score > 0:
        score += ph_score
        factors.append({"factor": "Phishing exposure", "contribution": ph_score})

    # Malicious extensions (max 12 pts)
    mal_score = min(12, malicious_count * 4)
    if mal_score > 0:
        score += mal_score
        factors.append({"factor": "Malicious extensions detected", "contribution": mal_score})

    # Email DLP leakage (max 8 pts)
    dlp_score = min(8, round(dlp_count / max(total, 1) * 8))
    if dlp_score > 0:
        score += dlp_score
        factors.append({"factor": "Email DLP events", "contribution": dlp_score})

    score = min(100, score)
    if score >= 75:
        grade = "D"
    elif score >= 50:
        grade = "C"
    elif score >= 25:
        grade = "B"
    else:
        grade = "A"

    return {"score": score, "grade": grade, "factors": sorted(factors, key=lambda x: x["contribution"], reverse=True)}


@router.get("/admin/risk-score")
def admin_risk_score(user=Depends(verify_supabase_jwt)):
    """
    Org-level risk score (0-100) + grade (A/B/C/D) + top risk factors.
    Also includes a 7-day trend comparison.
    """
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    all_incidents = _fetch_org_incidents(org_id)
    now = datetime.now(timezone.utc)
    week_ago  = now - timedelta(days=7)
    two_weeks = now - timedelta(days=14)

    this_week = [i for i in all_incidents if _parse_ts(i) and _parse_ts(i) >= week_ago]
    last_week = [
        i for i in all_incidents
        if _parse_ts(i) and two_weeks <= _parse_ts(i) < week_ago
    ]

    members_res = _sb().table("organization_members").select("user_id").eq("org_id", org_id).execute()
    total_members = len(members_res.data or [])

    current  = _compute_risk_score(all_incidents, total_members)
    prev_week = _compute_risk_score(last_week, total_members)

    return {
        "error": 0,
        "risk_score":      current["score"],
        "grade":           current["grade"],
        "trend_7d":        current["score"] - prev_week["score"],
        "top_risk_factors": current["factors"],
        "total_incidents": len(all_incidents),
        "this_week_count": len(this_week),
    }


def _parse_ts(i: dict):
    ts = i.get("timestamp") or i.get("created_at") or ""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


# ---------------------------------------------------------------------------
# GET /api/admin/risk-score/users  —  per-user risk scores, ranked
# ---------------------------------------------------------------------------

@router.get("/admin/risk-score/users")
def admin_risk_score_users(user=Depends(verify_supabase_jwt)):
    """
    Risk score for every org member, ranked highest risk first.
    Uses incident severity, unblocked count, and malicious extension events.
    """
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    incidents = _fetch_org_incidents(org_id)
    members_res = _sb().table("organization_members").select("user_id, role").eq("org_id", org_id).execute()
    members = members_res.data or []

    # Build per-user incident map
    user_incidents: Dict[str, list] = defaultdict(list)
    email_map: Dict[str, str] = {}
    for i in incidents:
        uid = i.get("user_id")
        if uid:
            user_incidents[uid].append(i)
            email_map.setdefault(uid, i.get("user_email", ""))

    ranked = []
    for m in members:
        uid = m["user_id"]
        u_incidents = user_incidents.get(uid, [])
        risk = _compute_risk_score(u_incidents, 1)
        ranked.append({
            "user_id":         uid,
            "email":           email_map.get(uid, ""),
            "role":            m.get("role"),
            "risk_score":      risk["score"],
            "grade":           risk["grade"],
            "top_factors":     risk["factors"][:3],
            "total_incidents": len(u_incidents),
            "critical_count":  sum(1 for i in u_incidents if i.get("severity") == "critical"),
            "high_count":      sum(1 for i in u_incidents if i.get("severity") == "high"),
        })

    ranked.sort(key=lambda x: x["risk_score"], reverse=True)
    return {"error": 0, "count": len(ranked), "users": ranked}


# ---------------------------------------------------------------------------
# GET /api/admin/threat-trends  —  month-over-month counts by category
# ---------------------------------------------------------------------------

@router.get("/admin/threat-trends")
def admin_threat_trends(
    months: int = Query(6, ge=1, le=12),
    user=Depends(verify_supabase_jwt),
):
    """
    Monthly incident counts per category for the last N months (default 6).
    Categories: secrets | phishing | email_dlp | extension | other
    ?months=3|6|12
    """
    ctx = _require_admin(user)
    incidents = _fetch_org_incidents(ctx["org_id"])
    now = datetime.now(timezone.utc)

    MONTH_NAMES = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]

    # Build ordered month buckets
    month_keys: List[str] = []
    for m in range(months - 1, -1, -1):
        target = now.replace(day=1) - timedelta(days=m * 30)
        month_keys.append(f"{MONTH_NAMES[target.month - 1]} {target.year}")

    # Zero-filled structure
    data: Dict[str, Dict[str, int]] = {
        mk: {"secrets": 0, "phishing": 0, "email_dlp": 0, "extension": 0, "other": 0, "total": 0}
        for mk in month_keys
    }

    for i in incidents:
        dt = _parse_ts(i)
        if not dt:
            continue
        mk = f"{MONTH_NAMES[dt.month - 1]} {dt.year}"
        if mk not in data:
            continue
        cat = _category(i)
        data[mk][cat] = data[mk].get(cat, 0) + 1
        data[mk]["total"] += 1

    trend = [{"month": mk, **counts} for mk, counts in data.items()]

    # Month-over-month delta for most recent two months
    delta = {}
    if len(trend) >= 2:
        curr, prev = trend[-1], trend[-2]
        for cat in ("secrets", "phishing", "email_dlp", "extension", "total"):
            p = prev.get(cat, 0) or 1
            delta[cat] = round((curr.get(cat, 0) - prev.get(cat, 0)) / p * 100, 1)

    return {
        "error": 0,
        "months": months,
        "trend": trend,
        "mom_change_pct": delta,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/top-threats  —  top N incidents by severity + recency
# ---------------------------------------------------------------------------

@router.get("/admin/top-threats")
def admin_top_threats(
    limit: int = Query(10, ge=1, le=50),
    severity: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    severity_type: Optional[str] = Query(None),
    user=Depends(verify_supabase_jwt),
):
    """
    Top incidents ranked by severity (critical > high > medium > low)
    then by recency. Use ?severity=critical|high to narrow.
    ?type= / ?severity_type= to filter by incident type.
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type

    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

    q = (
        _sb().table("incidents")
        .select("id, type, secret_type, severity, masked_preview, action, "
                "timestamp, user_email, tab_url, tab_title, browser_info, extensions, org_id")
        .eq("org_id", ctx["org_id"])
        .order("timestamp", desc=True)
        .limit(500)
    )
    if severity:
        q = q.eq("severity", severity)
    if effective_type:
        q = q.eq("type", effective_type)

    rows = q.execute().data or []

    # Sort: severity rank first, then timestamp desc (already sorted)
    rows.sort(key=lambda x: (SEV_ORDER.get(x.get("severity", "unknown"), 5), x.get("timestamp", "") and -1))
    top = rows[:limit]

    for r in top:
        r["category"] = _category(r)

    return {
        "error": 0,
        "count": len(top),
        "threats": top,
    }


# ===========================================================================
# USER & DEVICE GOVERNANCE
# ===========================================================================

# ---------------------------------------------------------------------------
# GET /api/admin/users/{user_id}/incidents
# ---------------------------------------------------------------------------

@router.get("/admin/users/{target_user_id}/incidents")
def admin_user_incidents(
    target_user_id: str,
    type: Optional[str] = Query(None),
    severity_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    page: int = Query(0, ge=0),
    page_size: int = Query(100, ge=1, le=500),
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    user=Depends(verify_supabase_jwt),
):
    """
    All incidents for a specific org member.
    ?type= / ?severity_type= / ?severity / date range / pagination all supported.
    """
    ctx = _require_admin(user)
    effective_type = type or severity_type

    # Verify user belongs to this org
    member_check = (
        _sb().table("organization_members")
        .select("user_id")
        .eq("org_id", ctx["org_id"])
        .eq("user_id", target_user_id)
        .execute()
    )
    if not member_check.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "User not found in this organization"})

    q = (
        _sb().table("incidents")
        .select("*", count="exact")
        .eq("org_id", ctx["org_id"])
        .eq("user_id", target_user_id)
        .order("timestamp", desc=True)
    )
    if effective_type:
        q = q.eq("type", effective_type)
    if severity:
        q = q.eq("severity", severity)
    if start_time:
        q = q.gte("timestamp", _to_iso(start_time, end_of_day=False))
    if end_time:
        q = q.lte("timestamp", _to_iso(end_time, end_of_day=True))
    q = q.range(page * page_size, (page + 1) * page_size - 1)

    res = q.execute()
    incidents = res.data or []
    total = res.count or len(incidents)

    by_type:    Dict[str, int] = defaultdict(int)
    by_severity: Dict[str, int] = defaultdict(int)
    by_category: Dict[str, int] = defaultdict(int)
    for i in incidents:
        by_type[(i.get("type") or "unknown")] += 1
        by_severity[(i.get("severity") or "unknown")] += 1
        by_category[_category(i)] += 1
        i["category"] = _category(i)

    return {
        "error": 0,
        "user_id": target_user_id,
        "count": len(incidents),
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, -(-total // page_size)),
        "by_type":     dict(by_type),
        "by_severity": dict(by_severity),
        "by_category": dict(by_category),
        "incidents": incidents,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/users/{user_id}/settings
# ---------------------------------------------------------------------------

@router.get("/admin/users/{target_user_id}/settings")
def admin_user_get_settings(
    target_user_id: str,
    user=Depends(verify_supabase_jwt),
):
    """Read user_settings for a specific org member."""
    ctx = _require_admin(user)

    member_check = (
        _sb().table("organization_members")
        .select("user_id")
        .eq("org_id", ctx["org_id"])
        .eq("user_id", target_user_id)
        .execute()
    )
    if not member_check.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "User not found in this organization"})

    res = _sb().table("user_settings").select("*").eq("user_id", target_user_id).execute()
    if not res.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Settings not found for this user"})

    return {"error": 0, "user_id": target_user_id, "settings": res.data[0]}


# ---------------------------------------------------------------------------
# PUT /api/admin/users/{user_id}/settings
# ---------------------------------------------------------------------------

@router.put("/admin/users/{target_user_id}/settings")
def admin_user_update_settings(
    target_user_id: str,
    body: AdminSettingsUpdate,
    user=Depends(verify_supabase_jwt),
):
    """
    Admin override — update user_settings for a specific org member.
    Only non-null fields in the request body are applied.
    """
    ctx = _require_admin(user)

    member_check = (
        _sb().table("organization_members")
        .select("user_id")
        .eq("org_id", ctx["org_id"])
        .eq("user_id", target_user_id)
        .execute()
    )
    if not member_check.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "User not found in this organization"})

    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "No fields provided to update"})

    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    _sb().table("user_settings").upsert({"user_id": target_user_id, **updates}, on_conflict="user_id").execute()

    res = _sb().table("user_settings").select("*").eq("user_id", target_user_id).execute()
    return {"error": 0, "user_id": target_user_id, "settings": res.data[0] if res.data else {}}


# ---------------------------------------------------------------------------
# GET /api/admin/devices  —  all unique devices seen across the org
# ---------------------------------------------------------------------------

@router.get("/admin/devices")
def admin_devices(user=Depends(verify_supabase_jwt)):
    """
    All unique browser_id values seen in org incidents, enriched with
    last-seen timestamp, extension version, browser_info, and incident count.
    """
    ctx = _require_admin(user)
    incidents = _fetch_org_incidents(ctx["org_id"])

    device_map: Dict[str, dict] = {}
    for i in incidents:
        bid = i.get("browser_id")
        if not bid:
            continue
        if bid not in device_map:
            device_map[bid] = {
                "browser_id":        bid,
                "user_email":        i.get("user_email", ""),
                "user_id":           i.get("user_id", ""),
                "extension_version": i.get("extension_version", ""),
                "browser_info":      i.get("browser_info") or {},
                "last_seen":         i.get("timestamp") or "",
                "incident_count":    0,
                "by_type":           defaultdict(int),
            }
        device_map[bid]["incident_count"] += 1
        itype = (i.get("type") or "unknown")
        device_map[bid]["by_type"][itype] += 1
        ts = i.get("timestamp") or ""
        if ts > device_map[bid]["last_seen"]:
            device_map[bid]["last_seen"] = ts
            device_map[bid]["extension_version"] = i.get("extension_version", "") or device_map[bid]["extension_version"]

    devices = []
    for d in device_map.values():
        d["by_type"] = dict(d["by_type"])
        devices.append(d)

    devices.sort(key=lambda x: x["last_seen"], reverse=True)

    return {
        "error": 0,
        "total_devices": len(devices),
        "devices": devices,
    }


# ---------------------------------------------------------------------------
# GET /api/admin/devices/{browser_id}  —  incident history for one device
# ---------------------------------------------------------------------------

@router.get("/admin/devices/{browser_id}")
def admin_device_detail(
    browser_id: str,
    page: int = Query(0, ge=0),
    page_size: int = Query(100, ge=1, le=500),
    user=Depends(verify_supabase_jwt),
):
    """Paginated incident history for a specific device (browser_id)."""
    ctx = _require_admin(user)

    q = (
        _sb().table("incidents")
        .select("*", count="exact")
        .eq("org_id", ctx["org_id"])
        .eq("browser_id", browser_id)
        .order("timestamp", desc=True)
    )
    q = q.range(page * page_size, (page + 1) * page_size - 1)
    res = q.execute()
    incidents = res.data or []
    total = res.count or len(incidents)

    if not incidents and page == 0:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Device not found or no incidents"})

    by_type:     Dict[str, int] = defaultdict(int)
    by_severity: Dict[str, int] = defaultdict(int)
    for i in incidents:
        by_type[(i.get("type") or "unknown")] += 1
        by_severity[(i.get("severity") or "unknown")] += 1
        i["category"] = _category(i)

    # Device summary from first incident
    first = incidents[0] if incidents else {}
    return {
        "error": 0,
        "browser_id": browser_id,
        "device_info": {
            "user_email":        first.get("user_email", ""),
            "user_id":           first.get("user_id", ""),
            "extension_version": first.get("extension_version", ""),
            "browser_info":      first.get("browser_info") or {},
        },
        "count": len(incidents),
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": max(1, -(-total // page_size)),
        "by_type":     dict(by_type),
        "by_severity": dict(by_severity),
        "incidents": incidents,
    }


# ===========================================================================
# DASHBOARD SUMMARY  —  single super-call for the main dashboard page
# ===========================================================================

@router.get("/admin/dashboard/summary")
def admin_dashboard_summary(user=Depends(verify_supabase_jwt)):
    """
    Returns everything the main IT-Admin dashboard needs in one request:
    - Risk score + grade + top factors
    - Category counts (secrets / phishing / email_dlp / extension / other)
    - Severity breakdown
    - Top 5 recent critical/high incidents
    - Team member count + active device count
    - This-week vs last-week incident delta
    - Per-category 7-day trend (daily counts)
    """
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    all_incidents = _fetch_org_incidents(org_id)
    now = datetime.now(timezone.utc)
    week_ago  = now - timedelta(days=7)
    two_weeks = now - timedelta(days=14)
    DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

    # ── Team & device counts ─────────────────────────────────────────────
    members_res = _sb().table("organization_members").select("user_id").eq("org_id", org_id).execute()
    total_members = len(members_res.data or [])
    devices = {i["browser_id"] for i in all_incidents if i.get("browser_id")}

    # ── Week slices ───────────────────────────────────────────────────────
    this_week = [i for i in all_incidents if _parse_ts(i) and _parse_ts(i) >= week_ago]
    last_week = [i for i in all_incidents if _parse_ts(i) and two_weeks <= _parse_ts(i) < week_ago]

    # ── Category & severity breakdowns ───────────────────────────────────
    cat_counts: Dict[str, int]  = defaultdict(int)
    sev_counts: Dict[str, int]  = defaultdict(int)
    action_counts: Dict[str, int] = defaultdict(int)
    for i in all_incidents:
        cat_counts[_category(i)] += 1
        sev_counts[(i.get("severity") or "unknown")] += 1
        action_counts[(i.get("action") or "unknown")] += 1

    # ── Risk score ────────────────────────────────────────────────────────
    risk = _compute_risk_score(all_incidents, total_members)

    # ── Top 5 critical/high incidents ─────────────────────────────────────
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    serious = [i for i in all_incidents if i.get("severity") in ("critical", "high")]
    serious.sort(key=lambda x: (SEV_ORDER.get(x.get("severity", "unknown"), 5),
                                 -(int(_parse_ts(x).timestamp()) if _parse_ts(x) else 0)))
    top5 = [
        {
            "id":           i.get("id"),
            "type":         i.get("type"),
            "category":     _category(i),
            "secret_type":  i.get("secret_type"),
            "severity":     i.get("severity"),
            "action":       i.get("action"),
            "timestamp":    i.get("timestamp"),
            "user_email":   i.get("user_email"),
            "tab_url":      i.get("tab_url"),
            "tab_title":    i.get("tab_title"),
            "masked_preview": i.get("masked_preview"),
        }
        for i in serious[:5]
    ]

    # ── 7-day per-category daily trend ───────────────────────────────────
    daily_trend: Dict[str, Dict[str, int]] = {}
    for d in range(6, -1, -1):
        day = (now - timedelta(days=d))
        key = day.strftime("%Y-%m-%d")
        daily_trend[key] = {
            "date":      key,
            "day":       DAY_NAMES[day.weekday()],
            "secrets":   0,
            "phishing":  0,
            "email_dlp": 0,
            "extension": 0,
            "other":     0,
            "total":     0,
        }
    for i in all_incidents:
        dt = _parse_ts(i)
        if not dt or (now - dt).days >= 7:
            continue
        key = dt.strftime("%Y-%m-%d")
        if key not in daily_trend:
            continue
        cat = _category(i)
        daily_trend[key][cat] = daily_trend[key].get(cat, 0) + 1
        daily_trend[key]["total"] += 1

    # ── Week-over-week delta ──────────────────────────────────────────────
    wow_delta = len(this_week) - len(last_week)
    wow_pct   = round(wow_delta / max(len(last_week), 1) * 100, 1)

    return {
        "error": 0,
        "org_id": org_id,
        "summary": {
            "total_incidents":     len(all_incidents),
            "this_week_incidents": len(this_week),
            "wow_delta":           wow_delta,
            "wow_delta_pct":       wow_pct,
            "total_members":       total_members,
            "active_devices":      len(devices),
            "threats_blocked":     action_counts.get("blocked", 0),
            "threats_masked":      action_counts.get("masked", 0),
        },
        "risk": {
            "score":   risk["score"],
            "grade":   risk["grade"],
            "trend_7d": risk["score"] - _compute_risk_score(last_week, total_members)["score"],
            "top_factors": risk["factors"][:3],
        },
        "category_breakdown": dict(cat_counts),
        "severity_breakdown":  dict(sev_counts),
        "action_breakdown":    dict(action_counts),
        "top_critical_incidents": top5,
        "daily_trend_7d": list(daily_trend.values()),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ORG GROUPS  ─  full CRUD + member management
#
#   GET    /api/admin/groups                         list groups + members
#   POST   /api/admin/groups                         create group
#   PUT    /api/admin/groups/{group_id}              rename group
#   DELETE /api/admin/groups/{group_id}              delete group
#   POST   /api/admin/groups/{group_id}/members      add member(s)
#   DELETE /api/admin/groups/{group_id}/members/{uid} remove member
# ─────────────────────────────────────────────────────────────────────────────

class GroupCreateBody(BaseModel):
    group_name: str

class GroupRenameBody(BaseModel):
    group_name: str

class GroupMembersAddBody(BaseModel):
    user_ids: List[str]          # one or more org member user_ids


def _build_groups_response(org_id: str) -> List[Dict[str, Any]]:
    """
    Fetches org_groups and org_group_members, enriches members with email
    using the incidents table (same pattern as /admin/team).
    Returns a list of group dicts ready to send to the client.
    """
    sb = _sb()

    # 1. All groups for this org
    groups_res = sb.table("org_groups").select("*").eq("org_id", org_id).order("created_at").execute()
    groups = groups_res.data or []

    # 2. All group members for this org (one query)
    members_res = sb.table("org_group_members").select("*").eq("org_id", org_id).execute()
    members_rows = members_res.data or []

    # 3. All org members to get roles
    org_members_res = sb.table("organization_members").select("user_id, role").eq("org_id", org_id).execute()
    role_map: Dict[str, str] = {m["user_id"]: m.get("role", "member") for m in (org_members_res.data or [])}

    # 4. Build email map from incidents (cheapest available source)
    email_map: Dict[str, str] = {}
    try:
        inc_res = (
            sb.table("incidents")
            .select("user_id, user_email")
            .eq("org_id", org_id)
            .limit(2000)
            .execute()
        )
        for row in (inc_res.data or []):
            uid = row.get("user_id")
            if uid and uid not in email_map and row.get("user_email"):
                email_map[uid] = row["user_email"]
    except Exception:
        pass

    # 5. Index members by group_id
    from collections import defaultdict as _dd
    members_by_group: Dict[str, List[Dict]] = _dd(list)
    for m in members_rows:
        gid = m["group_id"]
        uid = m["user_id"]
        members_by_group[gid].append({
            "user_id":  uid,
            "email":    email_map.get(uid, ""),
            "role":     role_map.get(uid, "member"),
            "added_at": m.get("added_at"),
        })

    # 6. Assemble final list
    result = []
    for g in groups:
        gid = g["id"]
        m_list = members_by_group.get(gid, [])
        result.append({
            "id":           gid,
            "group_name":   g.get("group_name", ""),
            "org_id":       g.get("org_id"),
            "member_count": len(m_list),
            "members":      m_list,
            "created_at":   g.get("created_at"),
        })
    return result


# ── GET /api/admin/groups ────────────────────────────────────────────────────

@router.get("/admin/groups")
def admin_get_groups(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    groups = _build_groups_response(ctx["org_id"])
    return {"error": 0, "groups": groups, "total": len(groups)}


# ── POST /api/admin/groups ───────────────────────────────────────────────────

@router.post("/admin/groups")
def admin_create_group(body: GroupCreateBody, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    name = body.group_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "group_name is required"})

    row = {
        "org_id":     org_id,
        "group_name": name,
        "created_by": ctx["user_id"],
    }
    try:
        res = _sb().table("org_groups").insert(row).execute()
        group = res.data[0] if res.data else row
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"error": 0, "group": {**group, "member_count": 0, "members": []}}


# ── PUT /api/admin/groups/{group_id} ─────────────────────────────────────────

@router.put("/admin/groups/{group_id}")
def admin_rename_group(group_id: str, body: GroupRenameBody, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    name = body.group_name.strip()
    if not name:
        raise HTTPException(status_code=400, detail={"error": 1, "message": "group_name is required"})

    # Verify group belongs to this org
    check = _sb().table("org_groups").select("id").eq("id", group_id).eq("org_id", org_id).execute()
    if not check.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Group not found"})

    _sb().table("org_groups").update({"group_name": name}).eq("id", group_id).execute()
    return {"error": 0, "group_id": group_id, "group_name": name}


# ── DELETE /api/admin/groups/{group_id} ──────────────────────────────────────

@router.delete("/admin/groups/{group_id}")
def admin_delete_group(group_id: str, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    check = _sb().table("org_groups").select("id").eq("id", group_id).eq("org_id", org_id).execute()
    if not check.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Group not found"})

    # Members are deleted via ON DELETE CASCADE in the DB
    _sb().table("org_groups").delete().eq("id", group_id).execute()
    return {"error": 0, "deleted": group_id}


# ── POST /api/admin/groups/{group_id}/members ────────────────────────────────

@router.post("/admin/groups/{group_id}/members")
def admin_add_group_members(group_id: str, body: GroupMembersAddBody, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    # Verify group belongs to this org
    check = _sb().table("org_groups").select("id").eq("id", group_id).eq("org_id", org_id).execute()
    if not check.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Group not found"})

    # Verify all user_ids are members of the org
    valid_members_res = (
        _sb().table("organization_members")
        .select("user_id")
        .eq("org_id", org_id)
        .in_("user_id", body.user_ids)
        .execute()
    )
    valid_ids = {m["user_id"] for m in (valid_members_res.data or [])}
    invalid = [uid for uid in body.user_ids if uid not in valid_ids]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail={"error": 1, "message": f"Users not in org: {invalid}"}
        )

    rows = [
        {"group_id": group_id, "org_id": org_id, "user_id": uid, "added_by": ctx["user_id"]}
        for uid in body.user_ids
    ]
    try:
        # upsert — ignore duplicates
        _sb().table("org_group_members").upsert(rows, on_conflict="group_id,user_id").execute()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"error": 0, "added": list(valid_ids), "group_id": group_id}


# ── DELETE /api/admin/groups/{group_id}/members/{user_id} ───────────────────

@router.delete("/admin/groups/{group_id}/members/{user_id}")
def admin_remove_group_member(group_id: str, user_id: str, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    check = _sb().table("org_groups").select("id").eq("id", group_id).eq("org_id", org_id).execute()
    if not check.data:
        raise HTTPException(status_code=404, detail={"error": 1, "message": "Group not found"})

    _sb().table("org_group_members").delete().eq("group_id", group_id).eq("user_id", user_id).execute()
    return {"error": 0, "removed": user_id, "group_id": group_id}


# ─────────────────────────────────────────────────────────────────────────────
# ORG CONTROLS  —  GET /api/admin/controls   PUT /api/admin/controls
# ─────────────────────────────────────────────────────────────────────────────

class ControlUpdateBody(BaseModel):
    control_id: str
    config: Dict[str, Any]


@router.get("/admin/controls")
def admin_get_controls(user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    try:
        res = _sb().table("org_controls").select("*").eq("org_id", org_id).execute()
        controls: Dict[str, Any] = {}
        for row in (res.data or []):
            controls[row["control_id"]] = row.get("config", {})
    except Exception:
        controls = {}

    return {"error": 0, "controls": controls}


@router.put("/admin/controls")
def admin_upsert_control(body: ControlUpdateBody, user=Depends(verify_supabase_jwt)):
    ctx = _require_admin(user)
    org_id = ctx["org_id"]

    row = {
        "org_id":     org_id,
        "control_id": body.control_id,
        "config":     body.config,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        _sb().table("org_controls").upsert(row, on_conflict="org_id,control_id").execute()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"error": 0, "control_id": body.control_id, "config": body.config}
