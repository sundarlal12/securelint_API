from typing import Any, Dict, List, Optional, Tuple

# Columns that are NOT boolean — always written with a fixed default value.
# These are skipped when building True/False feature flags.
_STATIC_FIELDS: Dict[str, Any] = {
    "masking_style":            "blur",
    "site_exclusions":          None,   # ARRAY
    "waf_social_domain":        None,   # ARRAY
    "enterprise_email_domains": None,   # ARRAY
    "email_dlp_domain":         None,   # ARRAY
    "email_dlp_action":         None,   # text
    "IT_mail":                  None,   # text
}

# Columns that are never feature flags (system / metadata columns)
_SKIP_COLUMNS = {"user_id", "updated_at", "Plans", "created_at"}

# Module-level cache so we only query the schema once per process startup
_cached_boolean_columns: Optional[Tuple[str, ...]] = None


def _get_all_features(supabase_client) -> Tuple[str, ...]:
    """
    Returns the tuple of boolean column names from user_settings dynamically
    by calling the get_user_settings_boolean_columns() Postgres function.
    Result is cached for the lifetime of the process.

    Requires this function to exist in Supabase:
        CREATE OR REPLACE FUNCTION get_user_settings_boolean_columns()
        RETURNS TABLE(col_name TEXT) AS $$
            SELECT column_name::TEXT
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name   = 'user_settings'
              AND data_type    = 'boolean'
            ORDER BY ordinal_position;
        $$ LANGUAGE sql SECURITY DEFINER;
    """
    global _cached_boolean_columns
    if _cached_boolean_columns is not None:
        return _cached_boolean_columns

    try:
        res = supabase_client.rpc("get_user_settings_boolean_columns").execute()
        if res.data:
            cols = tuple(
                row["col_name"] for row in res.data
                if row["col_name"] not in _SKIP_COLUMNS
                and row["col_name"] not in _STATIC_FIELDS
            )
            _cached_boolean_columns = cols
            print(f"[plan_features] loaded {len(cols)} boolean columns from user_settings schema")
            return _cached_boolean_columns
    except Exception as e:
        print(f"[plan_features] schema fetch failed, using empty feature set: {e}")

    return ()


def _fetch_plan_features(plan_id: str, supabase_client) -> List[str]:
    """
    Fetches the list of feature names the plan has access to from plan_settings.
    Raises RuntimeError if the table is unreachable or the plan has no rows.
    """
    res = (
        supabase_client
        .table("plan_settings")
        .select("feature")
        .eq("plan_name", plan_id.lower())
        .execute()
    )
    if not res.data:
        raise RuntimeError(f"No features found in plan_settings for plan='{plan_id}'")
    return [row["feature"] for row in res.data]


def _build_flags(plan_id: str, active_features: set, supabase_client) -> Dict[str, Any]:
    """
    Builds the full user_settings flags dict dynamically from the schema.
    Boolean columns in active_features → True, all others → False.
    Non-boolean columns written from _STATIC_FIELDS.
    """
    all_boolean_cols = _get_all_features(supabase_client)
    flags: Dict[str, Any] = {"Plans": plan_id.lower()}
    for col in all_boolean_cols:
        flags[col] = col in active_features
    flags.update(_STATIC_FIELDS)
    return flags


def build_settings_row(user_id: str, plan_id: str, supabase_client) -> Dict[str, Any]:
    """
    Returns a complete user_settings dict ready to INSERT at signup.
    Stores the real plan features from plan_settings table.
    The GET /api/settings endpoint gates access based on subscription status —
    features are returned as False there if subscription is inactive.
    """
    active = set(_fetch_plan_features(plan_id, supabase_client))
    return {"user_id": user_id, **_build_flags(plan_id, active, supabase_client)}


def apply_plan_settings(user_id: str, plan_id: str, supabase_client) -> None:
    """
    Upserts user_settings with the feature flags for plan_id.
    Boolean columns fetched dynamically from user_settings schema.
    Features the plan owns → True, all others → False.
    Called after a successful payment to unlock features.
    Logs errors but never raises (does not interrupt the payment response).
    """
    try:
        active = set(_fetch_plan_features(plan_id, supabase_client))
        row = {"user_id": user_id, **_build_flags(plan_id, active, supabase_client)}
        supabase_client.table("user_settings").upsert(
            row, on_conflict="user_id"
        ).execute()
        print(f"[plan_features] settings applied for user={user_id} plan={plan_id}")
    except Exception as e:
        print(f"[plan_features] ERROR applying settings for user={user_id}: {e}")
