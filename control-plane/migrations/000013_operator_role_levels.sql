-- ADR-016 §7 question 3, resolved: a single 'operator' role is not
-- enough -- the repository owner chose two levels (read-only visibility
-- vs. admin actions like stop-any-workload/revoke-any-key) over the
-- ADR's original one-level MVP assumption.
--
-- Existing 'operator' rows are promoted to 'operator_admin', not
-- 'operator_readonly': anyone already trusted with the old single
-- operator role already had admin-equivalent access under that role, so
-- downgrading them silently on this migration would be a surprise
-- privilege *removal*, not the fail-closed default this schema aims for
-- (see 000012's own DEFAULT 'tenant' reasoning for the same fail-closed
-- principle applied at grant time, not at migration time).
UPDATE users SET role = 'operator_admin' WHERE role = 'operator';

ALTER TABLE users DROP CONSTRAINT IF EXISTS users_role_check;
ALTER TABLE users ADD CONSTRAINT users_role_check
    CHECK (role IN ('tenant', 'operator_readonly', 'operator_admin'));
