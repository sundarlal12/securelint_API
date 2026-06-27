-- SecureLint: Coupon security hardening
-- Run AFTER 001_coupons_referrals.sql

-- 1. Add status column to coupon_redemptions
--    pending   = order created, payment not confirmed
--    committed = payment confirmed
--    cancelled = order abandoned / payment failed (slot freed)
ALTER TABLE coupon_redemptions
    ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'committed', 'cancelled'));

UPDATE coupon_redemptions
    SET status = 'committed'
    WHERE payment_transaction_id IS NOT NULL AND status = 'pending';

-- 2. Unique index: one active claim per (user, coupon)
--    Prevents a user from opening two browser tabs and creating two
--    orders with the same coupon simultaneously.
DROP INDEX IF EXISTS idx_redemptions_user_coupon;
CREATE UNIQUE INDEX idx_redemptions_active_user_coupon
    ON coupon_redemptions (user_id, coupon_id)
    WHERE status != 'cancelled';

-- 3. claim_coupon() — atomic check + increment + insert
--    Single DB transaction: lock row, check limits, increment current_uses,
--    insert pending redemption. Called at order-creation time.
CREATE OR REPLACE FUNCTION claim_coupon(
    p_coupon_id      uuid,
    p_user_id        uuid,
    p_plan_id        text,
    p_billing_period text,
    p_original_paise bigint,
    p_discount_paise bigint,
    p_final_paise    bigint,
    p_currency       text DEFAULT 'INR'
)
RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_coupon        coupons%ROWTYPE;
    v_active_uses   int;
    v_redemption_id uuid;
BEGIN
    -- Lock coupon row; concurrent calls for same coupon queue here.
    SELECT * INTO v_coupon FROM coupons WHERE id = p_coupon_id FOR UPDATE;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Coupon not found.');
    END IF;

    IF NOT v_coupon.is_active THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Coupon is no longer active.');
    END IF;

    -- Re-check global max_uses with the locked (fresh) row
    IF v_coupon.max_uses IS NOT NULL AND v_coupon.current_uses >= v_coupon.max_uses THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Coupon usage limit has been reached.');
    END IF;

    -- Count non-cancelled redemptions for this user (pending + committed)
    SELECT COUNT(*) INTO v_active_uses
    FROM coupon_redemptions
    WHERE coupon_id = p_coupon_id
      AND user_id   = p_user_id
      AND status   != 'cancelled';

    IF v_active_uses >= v_coupon.uses_per_user THEN
        RETURN jsonb_build_object('ok', false, 'error', 'You have already used this coupon.');
    END IF;

    -- Increment current_uses atomically
    UPDATE coupons SET current_uses = current_uses + 1 WHERE id = p_coupon_id;

    -- Insert pending redemption
    INSERT INTO coupon_redemptions (
        coupon_id, user_id,
        original_amount_paise, discount_amount_paise, final_amount_paise,
        currency, plan_id, billing_period, status
    ) VALUES (
        p_coupon_id, p_user_id,
        p_original_paise, p_discount_paise, p_final_paise,
        p_currency, p_plan_id, p_billing_period, 'pending'
    )
    RETURNING id INTO v_redemption_id;

    RETURN jsonb_build_object('ok', true, 'redemption_id', v_redemption_id::text);

EXCEPTION WHEN unique_violation THEN
    -- Unique index fired — roll back the increment
    UPDATE coupons SET current_uses = GREATEST(current_uses - 1, 0) WHERE id = p_coupon_id;
    RETURN jsonb_build_object('ok', false, 'error', 'You have already used this coupon.');
END;
$$;

-- 4. release_coupon() — cancel pending claim when order is abandoned
CREATE OR REPLACE FUNCTION release_coupon(p_redemption_id uuid)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
    v_coupon_id uuid;
    v_status    text;
BEGIN
    SELECT coupon_id, status INTO v_coupon_id, v_status
    FROM coupon_redemptions WHERE id = p_redemption_id FOR UPDATE;

    IF NOT FOUND OR v_status != 'pending' THEN RETURN; END IF;

    UPDATE coupon_redemptions SET status = 'cancelled' WHERE id = p_redemption_id;
    UPDATE coupons SET current_uses = GREATEST(current_uses - 1, 0) WHERE id = v_coupon_id;
END;
$$;

-- 5. commit_coupon() — move pending -> committed after payment confirmed
CREATE OR REPLACE FUNCTION commit_coupon(
    p_redemption_id          uuid,
    p_payment_transaction_id text
)
RETURNS void
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    UPDATE coupon_redemptions
    SET status                 = 'committed',
        payment_transaction_id = p_payment_transaction_id::uuid
    WHERE id     = p_redemption_id
      AND status = 'pending';
END;
$$;
