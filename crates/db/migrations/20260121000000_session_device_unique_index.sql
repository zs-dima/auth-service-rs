-- Add unique partial index on (id_user, device_id) for session upsert
-- This enables ON CONFLICT DO UPDATE for token refresh without creating duplicate sessions

-- Drop the trigger that expires old sessions (upsert replaces this behavior)
DROP TRIGGER IF EXISTS sessions_single_device_tr ON auth.sessions;
DROP FUNCTION IF EXISTS auth.sessions_expire_old_same_device();

-- Create unique partial index for upsert (only when device_id is NOT NULL)
-- Note: Cannot use CONCURRENTLY in SQLx migrations (runs in transaction)
CREATE UNIQUE INDEX IF NOT EXISTS session_user_device_ux
  ON auth.sessions (id_user, device_id)
  WHERE device_id IS NOT NULL;

COMMENT ON INDEX auth.session_user_device_ux IS 'Enables session upsert per user+device; prevents duplicate sessions';
