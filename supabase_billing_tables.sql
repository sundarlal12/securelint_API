-- ============================================================
-- SecureLint Billing Tables
-- Run this in Supabase → SQL Editor
-- ============================================================


-- ── 1. payment_transactions ──────────────────────────────────
-- Records every Razorpay order (pending → paid / failed)

CREATE TABLE IF NOT EXISTS payment_transactions (
    id                   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id              UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    plan_id              TEXT        NOT NULL,
    billing_period       TEXT        NOT NULL DEFAULT 'monthly',
    razorpay_order_id    TEXT        UNIQUE,
    razorpay_payment_id  TEXT        UNIQUE,
    razorpay_signature   TEXT,
    amount_paise         INTEGER     NOT NULL DEFAULT 0,
    currency             TEXT        NOT NULL DEFAULT 'INR',
    status               TEXT        NOT NULL DEFAULT 'created',
        -- created | paid | failed
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paid_at              TIMESTAMPTZ,
    metadata             JSONB       DEFAULT '{}'
);

-- Index for fast user history lookup
CREATE INDEX IF NOT EXISTS idx_payment_transactions_user
    ON payment_transactions(user_id, created_at DESC);

-- Index for order lookups during verify
CREATE INDEX IF NOT EXISTS idx_payment_transactions_order
    ON payment_transactions(razorpay_order_id);

-- RLS: users can only see their own transactions
ALTER TABLE payment_transactions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users see own transactions"
    ON payment_transactions FOR SELECT
    USING (auth.uid() = user_id);

-- Service role can do everything (backend uses service key)
CREATE POLICY "Service role full access"
    ON payment_transactions FOR ALL
    USING (true)
    WITH CHECK (true);


-- ── 2. Extend user_subscriptions ─────────────────────────────
-- Add billing columns if they don't exist yet

ALTER TABLE user_subscriptions
    ADD COLUMN IF NOT EXISTS billing_period      TEXT        DEFAULT 'monthly',
    ADD COLUMN IF NOT EXISTS starts_at           TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS ends_at             TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS razorpay_order_id   TEXT,
    ADD COLUMN IF NOT EXISTS razorpay_payment_id TEXT,
    ADD COLUMN IF NOT EXISTS updated_at          TIMESTAMPTZ DEFAULT NOW();

-- Auto-update updated_at on every change
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_user_subscriptions_updated_at ON user_subscriptions;
CREATE TRIGGER trg_user_subscriptions_updated_at
    BEFORE UPDATE ON user_subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();


-- ── 3. Verify tables exist ────────────────────────────────────
-- Run these SELECTs to confirm everything looks right:

-- SELECT * FROM payment_transactions LIMIT 5;
-- SELECT * FROM user_subscriptions LIMIT 5;
