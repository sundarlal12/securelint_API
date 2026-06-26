-- ═══════════════════════════════════════════════════════════════════════
-- SecureLint — Coupons & Referrals schema
-- Run this in the Supabase SQL editor (or via supabase db push)
-- ═══════════════════════════════════════════════════════════════════════

-- ── 1. coupons ────────────────────────────────────────────────────────
-- Stores all coupon codes (promo, referral, welcome, etc.)
CREATE TABLE IF NOT EXISTS coupons (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    code            text NOT NULL UNIQUE,           -- e.g. "SAVE20", "REF-ABC123"
    description     text,                           -- human label shown to user

    -- discount
    discount_type   text NOT NULL CHECK (discount_type IN ('percent', 'flat')),
    discount_value  numeric(10,2) NOT NULL,         -- 20 → 20%  or  500 → ₹500 off
    max_discount    numeric(10,2),                  -- cap for percent coupons (optional)
    min_order_amount numeric(10,2) DEFAULT 0,       -- minimum cart value to allow use

    -- scope
    source          text NOT NULL DEFAULT 'promo'   -- 'promo' | 'referral' | 'welcome'
                    CHECK (source IN ('promo', 'referral', 'welcome')),
    applicable_plans text[] DEFAULT NULL,           -- NULL = all plans, or ['pro','enterprise']
    applicable_periods text[] DEFAULT NULL,         -- NULL = all periods

    -- limits
    max_uses        int DEFAULT NULL,               -- NULL = unlimited
    uses_per_user   int DEFAULT 1,                  -- how many times one user can redeem
    current_uses    int NOT NULL DEFAULT 0,

    -- owner (for referral coupons only)
    owner_user_id   uuid REFERENCES auth.users(id) ON DELETE SET NULL,

    -- validity
    is_active       boolean NOT NULL DEFAULT true,
    valid_from      timestamptz NOT NULL DEFAULT now(),
    valid_until     timestamptz DEFAULT NULL,        -- NULL = never expires

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_coupons_code ON coupons (lower(code));
CREATE INDEX IF NOT EXISTS idx_coupons_owner ON coupons (owner_user_id) WHERE owner_user_id IS NOT NULL;


-- ── 2. coupon_redemptions ─────────────────────────────────────────────
-- One row per (user × coupon) redemption event
CREATE TABLE IF NOT EXISTS coupon_redemptions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    coupon_id       uuid NOT NULL REFERENCES coupons(id) ON DELETE RESTRICT,
    user_id         uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,

    -- what they paid / saved
    original_amount_paise  bigint NOT NULL,
    discount_amount_paise  bigint NOT NULL,
    final_amount_paise     bigint NOT NULL,
    currency               text NOT NULL DEFAULT 'INR',

    -- link to the payment that used this coupon
    payment_transaction_id uuid,                    -- FK set after order creation
    plan_id                text,
    billing_period         text,

    redeemed_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_redemptions_coupon ON coupon_redemptions (coupon_id);
CREATE INDEX IF NOT EXISTS idx_redemptions_user   ON coupon_redemptions (user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_redemptions_user_coupon
    ON coupon_redemptions (user_id, coupon_id)
    WHERE payment_transaction_id IS NOT NULL;     -- one committed redemption per user per coupon


-- ── 3. referrals ──────────────────────────────────────────────────────
-- Tracks who referred whom
CREATE TABLE IF NOT EXISTS referrals (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    referrer_id     uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    referee_id      uuid REFERENCES auth.users(id) ON DELETE SET NULL,  -- set on signup
    referee_email   text,                           -- captured before signup

    referral_code   text NOT NULL,                  -- the coupon code used / shared
    status          text NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'signed_up', 'paid', 'rewarded')),

    -- reward issued to referrer after referee pays
    reward_coupon_id uuid REFERENCES coupons(id) ON DELETE SET NULL,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals (referrer_id);
CREATE INDEX IF NOT EXISTS idx_referrals_code     ON referrals (referral_code);


-- ── 4. user referral codes ────────────────────────────────────────────
-- Every user gets one persistent personal referral code
-- (stored as a coupon row with source='referral' and owner_user_id set)
-- This view makes it easy to fetch a user's referral link.
CREATE OR REPLACE VIEW user_referral_codes AS
SELECT
    c.owner_user_id AS user_id,
    c.code          AS referral_code,
    c.current_uses,
    c.id            AS coupon_id
FROM coupons c
WHERE c.source = 'referral'
  AND c.owner_user_id IS NOT NULL;


-- ── 5. trigger: keep updated_at fresh ────────────────────────────────
CREATE OR REPLACE FUNCTION _set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = now(); RETURN NEW; END;
$$;

DROP TRIGGER IF EXISTS trg_coupons_updated_at   ON coupons;
CREATE TRIGGER trg_coupons_updated_at
    BEFORE UPDATE ON coupons
    FOR EACH ROW EXECUTE FUNCTION _set_updated_at();

DROP TRIGGER IF EXISTS trg_referrals_updated_at ON referrals;
CREATE TRIGGER trg_referrals_updated_at
    BEFORE UPDATE ON referrals
    FOR EACH ROW EXECUTE FUNCTION _set_updated_at();


-- ── 6. RLS policies ───────────────────────────────────────────────────
ALTER TABLE coupons             ENABLE ROW LEVEL SECURITY;
ALTER TABLE coupon_redemptions  ENABLE ROW LEVEL SECURITY;
ALTER TABLE referrals           ENABLE ROW LEVEL SECURITY;

-- coupons: any authenticated user can READ active coupons (to validate)
CREATE POLICY "coupons_read_active" ON coupons
    FOR SELECT TO authenticated
    USING (is_active = true);

-- coupon_redemptions: users see only their own
CREATE POLICY "redemptions_own" ON coupon_redemptions
    FOR ALL TO authenticated
    USING (user_id = auth.uid());

-- referrals: users see rows where they are referrer or referee
CREATE POLICY "referrals_own" ON referrals
    FOR ALL TO authenticated
    USING (referrer_id = auth.uid() OR referee_id = auth.uid());


-- ── 7. seed: example promo coupon ────────────────────────────────────
-- Remove this block before production if you don't want a default coupon.
INSERT INTO coupons (code, description, discount_type, discount_value, source, max_uses)
VALUES
    ('LAUNCH20',  'Launch special — 20% off any plan', 'percent', 20, 'promo', 500),
    ('WELCOME10', 'First purchase — ₹100 off',          'flat',    100, 'welcome', NULL)
ON CONFLICT (code) DO NOTHING;
