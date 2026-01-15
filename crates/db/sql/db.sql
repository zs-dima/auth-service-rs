-- Enable extensions for trigram index support
CREATE EXTENSION IF NOT EXISTS pg_trgm;


BEGIN;

-- Create auth schema and set search path for this transaction
CREATE SCHEMA IF NOT EXISTS auth;
SET LOCAL search_path = auth, public;

-- Schema-level security (uncomment for production)
-- REVOKE ALL ON SCHEMA auth FROM PUBLIC;
-- GRANT USAGE ON SCHEMA auth TO auth_service;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA auth TO auth_service;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA auth TO auth_service;
-- ALTER DEFAULT PRIVILEGES IN SCHEMA auth GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth_service;


-- =============================================================================
-- Domains with proper validation
-- =============================================================================

-- Email domain: lowercase normalized, validated format
-- Using TEXT + generated column approach for proper Unicode handling
CREATE DOMAIN email AS TEXT
  CHECK (
    VALUE = lower(VALUE) AND
    VALUE ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' AND
    length(VALUE) <= 254
  );
COMMENT ON DOMAIN email IS 'Email address - simple email validation';

-- Phone domain with E.164 format validation
CREATE DOMAIN phone_e164 AS TEXT
  CHECK (
    VALUE ~ '^\+[1-9][0-9]{1,14}$'
  );
COMMENT ON DOMAIN phone_e164 IS 'Phone number in E.164 format: +[country][number], 1-15 digits';

-- Role name (role id) domain
CREATE DOMAIN role_name AS TEXT
  CHECK (
    VALUE ~ '^[a-z][a-z0-9_]{0,62}$' AND
    VALUE = lower(VALUE)
  );
COMMENT ON DOMAIN role_name IS 'Role name/id: lowercase snake_case, 1-63 chars';

-- =============================================================================
-- Enums (Rust sqlx maps these with #[derive(sqlx::Type)])
-- =============================================================================

CREATE TYPE user_status AS ENUM (
  'pending',    -- Awaiting email/phone verification
  'active',     -- Fully active user
  'suspended',  -- Temporarily disabled
  'deleted'     -- Soft-deleted (retained for audit)
);

CREATE TYPE oauth_provider AS ENUM (
  'google',
  'github',
  'microsoft',
  'apple',
  'facebook'
);

-- =====================================================
-- ROLES TABLE - User roles with associated permissions
-- =====================================================
CREATE TABLE roles (
  id           role_name PRIMARY KEY, -- Role name
  description  TEXT,
  permissions  JSONB NOT NULL DEFAULT '{}'::JSONB,
  is_system    BOOLEAN NOT NULL DEFAULT FALSE,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at   TIMESTAMPTZ,                -- Soft-delete timestamp for roles
  CONSTRAINT role_permissions_valid_ck
    CHECK (jsonb_typeof(permissions) = 'object')
);
COMMENT ON TABLE roles IS 'User roles with associated permissions';
COMMENT ON COLUMN roles.permissions IS 'JSON object mapping permission keys to boolean or scope values';

-- Protect system roles
CREATE INDEX role_is_system_ix ON roles (is_system) WHERE is_system = TRUE;

-- =====================================================
-- USERS TABLE - User identity
-- =====================================================
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT uuidv7(), -- PK: UUIDv7 for time-ordered IDs
  role            role_name NOT NULL                 -- FK: restrict deletion if in use
                  CONSTRAINT user_role_fk
                  REFERENCES roles(id)
                  ON UPDATE CASCADE ON DELETE RESTRICT,

  -- Primary email and phone (from first OAuth provider or manually set)
  email           email,                     -- Email, UNIQUE by index for active
  email_verified  BOOLEAN NOT NULL DEFAULT FALSE,
  phone           phone_e164,
  phone_verified  BOOLEAN NOT NULL DEFAULT FALSE, -- Phone, E.164 format, UNIQUE by index for active

  -- Account status
  status          user_status NOT NULL DEFAULT 'active',

  -- Security
  password        TEXT -- Hashed password, NULL for OAuth-only users. Argon2id ~97 chars, bcrypt ~60 chars
                  CONSTRAINT user_password_hash_len_ck
                  CHECK (password IS NULL OR length(password) BETWEEN 50 AND 255),
  failed_login_attempts  SMALLINT NOT NULL DEFAULT 0
                         CONSTRAINT user_failed_login_range_ck
                         CHECK (failed_login_attempts BETWEEN 0 AND 100),
  locked_until           TIMESTAMPTZ,

  -- Timestamps
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),  -- Creation timestamp (UTC)
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),  -- Last update timestamp (UTC)
  deleted_at     TIMESTAMPTZ,                         -- Soft-delete timestamp (NULL if active)

  -- Ensure phone_verified is FALSE when phone is NULL
  CONSTRAINT user_phone_verified_ck
    CHECK (phone IS NOT NULL OR phone_verified = FALSE),

  -- Ensure email_verified is FALSE for pending users
  CONSTRAINT user_email_verified_ck
    CHECK (email IS NOT NULL OR email_verified = FALSE),

  -- Locked until must be in the future
  CONSTRAINT user_locked_until_ck
    CHECK (locked_until IS NULL OR locked_until > created_at),

  -- Active users must have either email or phone set
  CONSTRAINT user_auth_method_ck
    CHECK (status != 'active' OR email IS NOT NULL OR phone IS NOT NULL)
);
COMMENT ON TABLE users IS 'Core user accounts';
COMMENT ON COLUMN users.password IS 'Argon2id hashed password, NULL for OAuth-only accounts';
COMMENT ON COLUMN users.email IS 'Primary email address (stored lowercase for case-insensitive matching)';

-- Unique constraints for active users only (soft-delete friendly)
CREATE UNIQUE INDEX user_email_active_ux
  ON users (email)
  WHERE deleted_at IS NULL AND email IS NOT NULL;  -- no two active users can share the same email
CREATE UNIQUE INDEX user_phone_active_ux
  ON users (phone)
  WHERE deleted_at IS NULL AND phone IS NOT NULL;  -- no two active users share the same phone number

-- For admin queries on problem accounts
CREATE INDEX user_status_suspended_ix
  ON users (id)
  WHERE status IN ('suspended', 'pending') AND deleted_at IS NULL;

-- =====================================================
-- USER_PROFILES TABLE - 1:1 User information
-- =====================================================
CREATE TABLE user_profiles (
  id_user         UUID PRIMARY KEY
                  CONSTRAINT user_profile_id_user_fk
                  REFERENCES users(id) ON DELETE CASCADE,

  -- Display info
  display_name    TEXT NOT NULL
                  CONSTRAINT user_profile_display_name_len_ck
                  CHECK (length(display_name) BETWEEN 1 AND 100),
  display_name_normalized TEXT GENERATED ALWAYS AS (
    lower(normalize(display_name, NFC))
  ) STORED,             -- Normalized version for searching (NORMALIZE function)
  avatar_url      TEXT  -- From OAuth provider only
                  CONSTRAINT user_profile_avatar_url_ck
                  CHECK (
                    avatar_url IS NULL OR
                    (length(avatar_url) <= 2048 AND avatar_url ~ '^https?://')
                  ),
  locale          VARCHAR(35) NOT NULL DEFAULT 'en'  -- BCP 47 max length
                  CONSTRAINT user_profile_locale_ck
                  CHECK (locale ~ '^[a-z]{2,3}(-[A-Za-z]{4})?(-([A-Z]{2}|[0-9]{3}))?(-([A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*$'),
  timezone        VARCHAR(64) NOT NULL DEFAULT 'UTC'  -- IANA timezone
                  CONSTRAINT user_profile_timezone_ck
                  CHECK (timezone ~ '^[A-Za-z_]+(/[A-Za-z_]+)*$'),

  -- Optional extended info (JSON for flexibility)
  metadata        JSONB NOT NULL DEFAULT '{}'::JSONB
                  CONSTRAINT user_profile_metadata_ck
                  CHECK (jsonb_typeof(metadata) = 'object'),

  -- Timestamps
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
COMMENT ON TABLE user_profiles IS 'Extended user profile information';
COMMENT ON COLUMN user_profiles.display_name_normalized IS 'NFC-normalized lowercase display name for searching';

-- Trigram index on normalized name for fuzzy search
CREATE INDEX user_profile_display_name_trgm_ix
  ON user_profiles
  USING GIN (display_name_normalized gin_trgm_ops);

-- =====================================================
-- PROVIDERS TABLE - OAuth provider connections
-- =====================================================
-- Allows multiple providers per user (Google, Apple, GitHub, etc.)
CREATE TABLE providers (
  id_user         UUID NOT NULL
                  CONSTRAINT provider_id_user_fk
                  REFERENCES users(id) ON DELETE CASCADE,

  -- Provider identification
  provider        oauth_provider NOT NULL, -- 'Google', 'GitHub', etc.
  provider_uid    TEXT NOT NULL                 -- Provider's unique user ID
                  CONSTRAINT provider_provider_uid_len_ck
                  CHECK (length(provider_uid) BETWEEN 1 AND 255),

  -- Provider-supplied data
  email           email,         -- Email from this provider
  name            VARCHAR(255),  -- Name from provider
  avatar_url      TEXT,          -- Avatar from provider
  provider_data   JSONB NOT NULL DEFAULT '{}'::JSONB
                  CONSTRAINT provider_provider_data_ck
                  CHECK (jsonb_typeof(provider_data) = 'object'),

  -- OAuth scopes granted (stored as JSON array)
  scopes          JSONB NOT NULL DEFAULT '[]'::JSONB
                  CONSTRAINT provider_scopes_ck
                  CHECK (jsonb_typeof(scopes) = 'array'),

  -- Timestamps
  linked_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at   TIMESTAMPTZ,
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  PRIMARY KEY(id_user, provider)
);
COMMENT ON TABLE providers IS 'OAuth provider links for federated authentication';

-- Unique constraint: one user per provider account
CREATE UNIQUE INDEX provider_provider_uid_ux
  ON providers (provider, provider_uid);

-- Index for user lookups
CREATE INDEX provider_id_user_ix
  ON providers (id_user);

CREATE INDEX provider_email_ix
  ON providers (email) WHERE email IS NOT NULL;

-- =====================================================
-- OAUTH_STATES TABLE - Temporary PKCE state storage
-- =====================================================
-- Stores OAuth2 PKCE flow state and code verifier
-- Entries should be cleaned up after use or expiration (5 minutes TTL)
CREATE TABLE oauth_states (
  id              UUID PRIMARY KEY DEFAULT uuidv7(),

  -- OAuth2 state parameter (random string)
  state           VARCHAR(255) NOT NULL UNIQUE,

  -- PKCE code verifier
  code_verifier   VARCHAR(128) NOT NULL,

  -- Provider identifier
  provider        oauth_provider NOT NULL, -- 'Google', 'GitHub', etc.

  -- Optional redirect URI override
  redirect_uri    TEXT,

  -- Expiration
  expires_at      TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '5 minutes',

  -- Creation timestamp
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oauth_state_state_ix
  ON oauth_states(state);
CREATE INDEX oauth_state_expires_ix
  ON oauth_states(expires_at);

-- Partition by month for large-scale (optional, uncomment if needed)
-- CREATE INDEX auth_event_partition_ix ON auth_events(created_at);

-- =====================================================
-- SESSIONS TABLE - Active sessions (no separate refresh token)
-- =====================================================
-- Session token is embedded in JWT access token for refresh
CREATE TABLE sessions (
  id_user        UUID NOT NULL
                 CONSTRAINT session_id_user_fk
                 REFERENCES users(id) ON DELETE CASCADE,

  -- Client info
  device_id      TEXT
                 CONSTRAINT session_device_id_ck
                 CHECK (device_id IS NULL OR length(device_id) BETWEEN 1 AND 255),
  device_name    TEXT
                 CONSTRAINT session_device_name_ck
                 CHECK (device_name IS NULL OR length(device_name) <= 255),       -- "iPhone 15 Pro", "Chrome on macOS"
  device_type    TEXT
                 CONSTRAINT session_device_type_ck
                 CHECK (device_type IS NULL OR length(device_type) <= 50),        -- 'mobile', 'tablet', 'desktop', 'unknown'
  client_version TEXT
                 CONSTRAINT session_client_version_ck
                 CHECK (client_version IS NULL OR length(client_version) <= 100), -- App version if applicable

  -- Network info
  ip_created_by  INET,               -- IP at session creation
  ip_address     INET,               -- Last seen IP
  ip_country     VARCHAR(2)
                 CONSTRAINT session_country_ck
                 CHECK (ip_country IS NULL OR ip_country ~ '^[A-Z]{2}$'),         -- ISO country code from IP

  -- Token storage (SHA-256 = 32 bytes, hash of the actual token)
  -- SELECT encode(refresh_token, 'hex') AS token_hex FROM
  refresh_token  BYTEA PRIMARY KEY NOT NULL
                 CONSTRAINT session_token_len_ck
                 CHECK (octet_length(refresh_token) = 32),

  -- Session metadata (user agent, IP, device fingerprint)
  metadata       JSONB NOT NULL DEFAULT '{}'::JSONB
                 CONSTRAINT session_metadata_ck
                 CHECK (jsonb_typeof(metadata) = 'object'),

  -- Activity tracking
  expires_at     TIMESTAMPTZ NOT NULL, -- Session validity
  last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  activity_count INTEGER NOT NULL DEFAULT 0,    -- Number of token refreshes

  -- Timestamps
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT session_expires_ck
    CHECK (expires_at > created_at)
);
COMMENT ON TABLE sessions IS 'User sessions - validity controlled solely by expires_at';
COMMENT ON COLUMN sessions.refresh_token IS 'SHA-256 hash of the refresh token (32 bytes)';

-- Active sessions per user
CREATE INDEX session_id_user_ix
  ON sessions (id_user, expires_at DESC);

-- Cleanup job index (find expired sessions to delete)
CREATE INDEX session_expires_at_ix
  ON sessions (expires_at);

-- =====================================================
-- PASSWORD_RESET_TOKENS TABLE - Password reset tokens
-- =====================================================
-- Stores secure password reset tokens with expiration.
-- Tokens are single-use and expire after a short period.
CREATE TABLE password_reset_tokens (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  id_user       UUID NOT NULL
                CONSTRAINT password_reset_id_user_fk
                REFERENCES users(id) ON DELETE CASCADE,

  -- Token storage (SHA-256 = 32 bytes, hash of the actual token)
  token_hash    BYTEA NOT NULL
                CONSTRAINT password_reset_token_len_ck
                CHECK (octet_length(token_hash) = 32),

  -- Expiration and usage tracking
  expires_at    TIMESTAMPTZ NOT NULL,
  used_at       TIMESTAMPTZ,       -- NULL if not yet used, set when consumed
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT password_reset_expires_ck
    CHECK (expires_at > created_at)
);
COMMENT ON TABLE password_reset_tokens IS 'Password reset tokens - single use, short expiry';
COMMENT ON COLUMN password_reset_tokens.token_hash IS 'SHA-256 hash of the reset token (32 bytes)';

-- Index for token lookup
CREATE INDEX password_reset_token_hash_ix
  ON password_reset_tokens (token_hash)
  WHERE used_at IS NULL;

-- Index for cleanup job
CREATE INDEX password_reset_expires_ix
  ON password_reset_tokens (expires_at);

-- Index for finding user's active tokens
CREATE INDEX password_reset_user_ix
  ON password_reset_tokens (id_user, expires_at DESC)
  WHERE used_at IS NULL;

-- =====================================================
-- EMAIL_VERIFICATION_TOKENS TABLE
-- =====================================================
-- Stores secure email verification tokens with expiration.
-- Tokens are single-use and expire after a configurable period.
CREATE TABLE email_verification_tokens (
  id            UUID PRIMARY KEY DEFAULT uuidv7(),
  id_user       UUID NOT NULL
                CONSTRAINT email_verification_id_user_fk
                REFERENCES users(id) ON DELETE CASCADE,

  -- Token storage (SHA-256 = 32 bytes, hash of the actual token)
  token_hash    BYTEA NOT NULL
                CONSTRAINT email_verification_token_len_ck
                CHECK (octet_length(token_hash) = 32),

  -- Expiration and usage tracking
  expires_at    TIMESTAMPTZ NOT NULL,
  used_at       TIMESTAMPTZ,       -- NULL if not yet used, set when consumed
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT email_verification_expires_ck
    CHECK (expires_at > created_at)
);
COMMENT ON TABLE email_verification_tokens IS 'Email verification tokens - single use, configurable expiry';
COMMENT ON COLUMN email_verification_tokens.token_hash IS 'SHA-256 hash of the verification token (32 bytes)';

-- Index for token lookup
CREATE INDEX email_verification_token_hash_ix
  ON email_verification_tokens (token_hash)
  WHERE used_at IS NULL;

-- Index for cleanup job
CREATE INDEX email_verification_expires_ix
  ON email_verification_tokens (expires_at);

-- Index for finding user's active tokens
CREATE INDEX email_verification_user_ix
  ON email_verification_tokens (id_user, expires_at DESC)
  WHERE used_at IS NULL;

-- =============================================================================
-- FUNCTIONS
-- =============================================================================

-- Normalize email before insert/update (ensures consistency)
CREATE OR REPLACE FUNCTION auth.normalize_email(p_email TEXT)
RETURNS auth.email
LANGUAGE SQL
IMMUTABLE
STRICT          -- Returns NULL if input is NULL (avoids unnecessary processing)
PARALLEL SAFE
LEAKPROOF       -- Prevents information leakage in security contexts
SET search_path = auth, public -- prevents search_path injection attacks
RETURN lower(trim(p_email));

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION auth.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER  -- Explicit: runs with caller's privileges
SET search_path = auth, public
AS $$
BEGIN
  NEW.updated_at = clock_timestamp();
  RETURN NEW;
END;
$$;

-- Create user with profile atomically (supports email OR phone registration)
-- Returns: UUID of created user
-- Raises: unique_violation if email/phone exists, foreign_key_violation if role doesn't exist
CREATE OR REPLACE FUNCTION auth.create_user_with_profile(
  p_email TEXT DEFAULT NULL,
  p_phone TEXT DEFAULT NULL,
  p_password_hash TEXT DEFAULT NULL,
  p_role auth.role_name DEFAULT 'user',
  p_display_name TEXT DEFAULT NULL,
  p_locale VARCHAR(35) DEFAULT 'en',
  p_timezone VARCHAR(64) DEFAULT 'UTC'
)
RETURNS UUID
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
AS $$
DECLARE
  v_id_user UUID;
  v_display_name TEXT;
  v_normalized_email auth.email;
  v_normalized_phone auth.phone_e164;
BEGIN
  -- Validate at least one identifier
  IF p_email IS NULL AND p_phone IS NULL THEN
    RAISE EXCEPTION 'Either email or phone must be provided'
      USING ERRCODE = 'invalid_parameter_value';
  END IF;

  -- Normalize identifiers
  IF p_email IS NOT NULL THEN
    v_normalized_email := auth.normalize_email(p_email);
  END IF;
  
  IF p_phone IS NOT NULL THEN
    v_normalized_phone := p_phone::auth.phone_e164;
  END IF;

  -- Derive display name: provided > email username > 'User'
  v_display_name := COALESCE(
    NULLIF(trim(p_display_name), ''),
    CASE WHEN p_email IS NOT NULL THEN split_part(p_email, '@', 1) ELSE 'User' END
  );

  INSERT INTO auth.users (email, phone, password, role)
  VALUES (v_normalized_email, v_normalized_phone, p_password_hash, p_role)
  RETURNING id INTO v_id_user;

  INSERT INTO auth.user_profiles (id_user, display_name, locale, timezone)
  VALUES (v_id_user, v_display_name, p_locale, p_timezone);

  RETURN v_id_user;
END;
$$;
COMMENT ON FUNCTION auth.create_user_with_profile IS 'Atomically creates user and profile; supports email or phone registration';

-- Link OAuth provider to user (stores OAuth name and avatar when available)
-- Returns id_user on success (INSERT or UPDATE)
-- Uses ON CONFLICT for atomic upsert
CREATE OR REPLACE FUNCTION auth.link_oauth_provider(
  p_id_user UUID,
  p_provider auth.oauth_provider,
  p_provider_uid TEXT,
  p_email TEXT DEFAULT NULL,
  p_name TEXT DEFAULT NULL,
  p_avatar_url TEXT DEFAULT NULL,
  p_provider_data JSONB DEFAULT '{}'::JSONB
)
RETURNS UUID
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
AS $$
DECLARE
  v_id_user UUID;
BEGIN
  INSERT INTO auth.providers (
    id_user, provider, provider_uid,
    email, name, avatar_url, provider_data, last_login_at
  )
  VALUES (
    p_id_user, p_provider, p_provider_uid,
    CASE WHEN p_email IS NOT NULL THEN auth.normalize_email(p_email) END,
    p_name,
    p_avatar_url,
    COALESCE(p_provider_data, '{}'::JSONB),
    now()
  )
  ON CONFLICT (id_user, provider) DO UPDATE SET
    provider_uid = EXCLUDED.provider_uid,
    email = EXCLUDED.email,
    name = EXCLUDED.name,
    avatar_url = EXCLUDED.avatar_url,
    provider_data = auth.providers.provider_data || EXCLUDED.provider_data,  -- Merge, don't replace
    last_login_at = now(),
    updated_at = now()
  RETURNING id_user INTO v_id_user;

  RETURN v_id_user;
END;
$$;
COMMENT ON FUNCTION auth.link_oauth_provider IS 'Upserts OAuth provider link; merges provider_data on update';

-- =============================================================================
-- SESSION MANAGEMENT FUNCTIONS
-- =============================================================================
-- Session revocation scenarios:
-- 1) Explicit logout by user          → SQLx: DELETE by token_hash
-- 2) User terminates from settings    → SQLx: DELETE by token_hash + user_id
-- 3) Same user_id + device_id login   → Trigger: sessions_single_device_tr (soft-expire)
-- 4) Session lifetime expired         → Query: expires_at check + cleanup job
--
-- Design rationale:
-- - Simple CRUD (revoke) → SQLx queries (compile-time checks, easier to modify)
-- - Complex atomic ops   → DB functions (touch_session, consume_oauth_state)
-- - Batch operations     → DB functions (cleanup jobs)
-- =============================================================================

-- Validate and refresh session (sliding expiration)
-- Atomic: updates + returns in single round-trip, prevents race conditions
-- Returns session owner and new expiry if valid, empty set if expired/not found
CREATE OR REPLACE FUNCTION auth.touch_session(
  p_token_hash BYTEA,
  p_extend_by INTERVAL DEFAULT INTERVAL '7 days',
  p_ip_address INET DEFAULT NULL,
  p_ip_country VARCHAR(2) DEFAULT NULL
)
RETURNS TABLE (
  id_user UUID,          -- Session owner (for JWT generation)
  expires_at TIMESTAMPTZ -- New expiration (for JWT exp claim)
)
LANGUAGE SQL
VOLATILE        -- Performs UPDATE
SECURITY INVOKER
PARALLEL UNSAFE -- Modifies data
SET search_path = auth, public
AS $$
  UPDATE auth.sessions s
  SET
    last_seen_at = now(),
    expires_at = now() + p_extend_by,
    activity_count = s.activity_count + 1,
    ip_address = COALESCE(p_ip_address, s.ip_address),
    ip_country = COALESCE(p_ip_country, s.ip_country)
  WHERE s.refresh_token = p_token_hash
    AND s.expires_at > now()
  RETURNING s.id_user, s.expires_at;
$$;
COMMENT ON FUNCTION auth.touch_session IS 'Validates and extends session; returns (user_id, new_expiry) or empty if invalid';

-- =============================================================================
-- SESSION REVOCATION - Recommended as SQLx queries for simplicity
-- =============================================================================
-- These are simple DELETE operations. Keeping as functions for reference,
-- but consider using direct SQLx queries in Rust for better type safety:
--
-- Revoke single session (logout):
--   DELETE FROM auth.sessions WHERE refresh_token = $1 RETURNING id_user
--
-- Revoke user's session (settings screen):
--   DELETE FROM auth.sessions WHERE refresh_token = $1 AND id_user = $2 RETURNING TRUE
--
-- Revoke all user sessions:
--   DELETE FROM auth.sessions WHERE id_user = $1 AND expires_at > now()
--
-- Revoke other sessions (keep current):
--   DELETE FROM auth.sessions WHERE id_user = $1 AND refresh_token <> $2 AND expires_at > now()
--
-- List user sessions (settings screen):
--   SELECT device_id, device_name, device_type, client_version, ip_address, ip_country,
--          created_at, last_seen_at, expires_at,
--          (refresh_token = $2) AS is_current
--   FROM auth.sessions WHERE id_user = $1 AND expires_at > now()
--   ORDER BY last_seen_at DESC
-- =============================================================================

-- Revoke session (for explicit logout)
-- Returns id_user if session was found and revoked, NULL otherwise
CREATE OR REPLACE FUNCTION auth.revoke_session(p_token_hash BYTEA)
RETURNS UUID
LANGUAGE SQL
STRICT          -- Returns NULL if input is NULL
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
AS $$
  DELETE FROM auth.sessions
  WHERE refresh_token = p_token_hash
  RETURNING id_user;
$$;
COMMENT ON FUNCTION auth.revoke_session IS 'Deletes session by token hash; returns user_id if found';

-- Revoke all active sessions for user (logout everywhere)
-- Returns count of sessions revoked
CREATE OR REPLACE FUNCTION auth.revoke_all_user_sessions(p_id_user UUID)
RETURNS INT
LANGUAGE plpgsql
STRICT          -- Returns NULL if input is NULL
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
AS $$
DECLARE
  v_count INT;
BEGIN
  DELETE FROM auth.sessions
  WHERE id_user = p_id_user
    AND expires_at > now();
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;
COMMENT ON FUNCTION auth.revoke_all_user_sessions IS 'Revokes all active sessions for user; returns count deleted';

-- Revoke all sessions EXCEPT current (logout other devices)
-- Returns count of sessions revoked
CREATE OR REPLACE FUNCTION auth.revoke_other_sessions(
  p_id_user UUID,
  p_current_token_hash BYTEA
)
RETURNS INT
LANGUAGE plpgsql
STRICT
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
AS $$
DECLARE
  v_count INT;
BEGIN
  DELETE FROM auth.sessions
  WHERE id_user = p_id_user
    AND refresh_token <> p_current_token_hash
    AND expires_at > now();
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;
COMMENT ON FUNCTION auth.revoke_other_sessions IS 'Revokes all sessions except current; returns count deleted';

-- Cleanup expired sessions (run periodically via pg_cron or app scheduler)
-- Deletes sessions that have been expired for at least p_grace_period
-- Grace period allows for clock skew and late requests
-- Recommended: Run every hour with default 1-day grace period
CREATE OR REPLACE FUNCTION auth.cleanup_expired_sessions(
  p_grace_period INTERVAL DEFAULT INTERVAL '1 day',
  p_batch_size INT DEFAULT 10000
)
RETURNS INT
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
SET lock_timeout = '5s'  -- Prevent long waits on locks
AS $$
DECLARE
  v_count INT := 0;
  v_deleted INT;
  v_cutoff TIMESTAMPTZ;
BEGIN
  v_cutoff := clock_timestamp() - p_grace_period;
  
  -- Delete in batches to avoid long locks and reduce WAL pressure
  LOOP
    DELETE FROM auth.sessions
    WHERE refresh_token IN (
      SELECT refresh_token
      FROM auth.sessions
      WHERE expires_at < v_cutoff
      LIMIT p_batch_size
      FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    v_count := v_count + v_deleted;
    EXIT WHEN v_deleted < p_batch_size;
    -- Brief pause to allow other transactions
    PERFORM pg_sleep(0.05);
    COMMIT;  -- Release locks between batches
  END LOOP;
  RETURN v_count;
END;
$$;
COMMENT ON FUNCTION auth.cleanup_expired_sessions IS 'Batch-deletes expired sessions; run hourly via pg_cron';

-- Cleanup expired OAuth states (run with cleanup_expired_sessions)
-- Returns count of deleted states
CREATE OR REPLACE FUNCTION auth.cleanup_expired_oauth_states(
  p_batch_size INT DEFAULT 1000
)
RETURNS INT
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
SET lock_timeout = '5s'
AS $$
DECLARE
  v_count INT := 0;
  v_deleted INT;
BEGIN
  LOOP
    DELETE FROM auth.oauth_states
    WHERE id IN (
      SELECT id
      FROM auth.oauth_states
      WHERE expires_at < now()
      LIMIT p_batch_size
      FOR UPDATE SKIP LOCKED
    );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    v_count := v_count + v_deleted;
    EXIT WHEN v_deleted < p_batch_size;
    PERFORM pg_sleep(0.01);
  END LOOP;
  RETURN v_count;
END;
$$;
COMMENT ON FUNCTION auth.cleanup_expired_oauth_states IS 'Batch-deletes expired OAuth states; run every 15 min via pg_cron';

-- Consume OAuth state (atomic get-and-delete for PKCE flow)
-- Returns the state data if valid, NULL if not found or expired
-- CRITICAL: Single-use token - delete on read prevents replay attacks
CREATE OR REPLACE FUNCTION auth.consume_oauth_state(p_state VARCHAR(255))
RETURNS TABLE (
  code_verifier VARCHAR(128),
  provider auth.oauth_provider,
  redirect_uri TEXT
)
LANGUAGE SQL
STRICT          -- Returns NULL if input is NULL
VOLATILE
SECURITY INVOKER
PARALLEL UNSAFE
SET search_path = auth, public
AS $$
  DELETE FROM auth.oauth_states
  WHERE state = p_state
    AND expires_at > now()
  RETURNING code_verifier, provider, redirect_uri;
$$;
COMMENT ON FUNCTION auth.consume_oauth_state IS 'Atomically consumes OAuth state for PKCE; prevents replay attacks';

-- =============================================================================
-- TRIGGERS
-- =============================================================================

CREATE TRIGGER role_updated_at_tr
  BEFORE UPDATE ON roles
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();

CREATE TRIGGER users_updated_at_tr
  BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();

CREATE TRIGGER user_profiles_updated_at_tr
  BEFORE UPDATE ON user_profiles
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();

CREATE TRIGGER providers_updated_at_tr
  BEFORE UPDATE ON providers
  FOR EACH ROW EXECUTE FUNCTION auth.set_updated_at();

-- Auto-expire any existing session for same user and device (ensure single active session per device)
CREATE OR REPLACE FUNCTION auth.sessions_expire_old_same_device()
RETURNS TRIGGER
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = auth, public
AS $$
BEGIN
  IF NEW.device_id IS NOT NULL THEN
    UPDATE auth.sessions
    SET expires_at = clock_timestamp()
    WHERE id_user = NEW.id_user
      AND device_id = NEW.device_id
      AND expires_at > clock_timestamp()
      AND refresh_token <> NEW.refresh_token;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER sessions_single_device_tr
  AFTER INSERT ON sessions
  FOR EACH ROW EXECUTE FUNCTION auth.sessions_expire_old_same_device();

-- =============================================================================
-- V_USERS_FULL VIEW
-- =============================================================================
CREATE OR REPLACE VIEW auth.v_users_full
WITH (security_invoker = true)  -- PG15+ security best practice
AS
SELECT
  u.id,
  u.email,
  u.email_verified,
  u.phone,
  u.phone_verified,
  u.status,
  u.role,
  r.permissions AS role_permissions,
  u.created_at,
  u.updated_at,           -- Cache invalidation / ETag support
  p.display_name,
  p.avatar_url,
  -- p.avatar_blurhash,
  p.locale,
  p.timezone,
  COALESCE(
    jsonb_agg(
      jsonb_build_object(
        'provider', ap.provider,
        'email', ap.email,
        'linked_at', ap.linked_at,
        'last_login_at', ap.last_login_at
      ) ORDER BY ap.linked_at  -- Deterministic ordering
    ) FILTER (WHERE ap.provider IS NOT NULL),
    '[]'::JSONB
  ) AS providers,
  (SELECT COUNT(*)::INT
   FROM auth.sessions s
   WHERE s.id_user = u.id
     AND s.expires_at > now()
  ) AS active_sessions
FROM auth.users u
LEFT JOIN auth.roles r ON r.id = u.role
LEFT JOIN auth.user_profiles p ON p.id_user = u.id
LEFT JOIN auth.providers ap ON ap.id_user = u.id
WHERE u.deleted_at IS NULL
GROUP BY u.id, r.id, p.id_user;
COMMENT ON VIEW auth.v_users_full IS 'Complete user view with profile, role, and OAuth providers';


-- =====================================================
-- SEED DATA - Test roles and user
-- =====================================================
INSERT INTO auth.roles (id, description, permissions, is_system) VALUES
  ('admin', 'Full system administrator', '{"*": true}'::JSONB, TRUE),
  ('user', 'Standard user account', '{"profile:read": true, "profile:write": true}'::JSONB, TRUE),
  ('guest', 'Limited guest access', '{"profile:read": true}'::JSONB, TRUE)
ON CONFLICT (id) DO NOTHING;

-- Test user for development/testing
-- UUID: 00000000-0000-0000-0000-000000000001 (matches JWT generation for --gen-jwt flag)
INSERT INTO auth.users (id, role, email, email_verified, status, password, created_at, updated_at)
VALUES ('00000000-0000-0000-0000-000000000001'::uuid, 'admin', 'test@gmail.com', TRUE, 'active', '$argon2id$v=19$m=19456,t=2,p=1$PtV5kR1F+sLB6DQUuQa8sQ$Gw0lWUGlhnoCMBtGzTXqgQ8D03Z05cjxgWWef6knpGE', NOW(), NOW())
ON CONFLICT DO NOTHING;

-- Create profile for test user
INSERT INTO auth.user_profiles (id_user, display_name, avatar_url, locale, timezone, created_at, updated_at)
SELECT u.id, 'Test User', NULL, 'en', 'UTC', NOW(), NOW()
FROM auth.users u
WHERE u.email = 'test@gmail.com'
  AND NOT EXISTS (SELECT 1 FROM auth.user_profiles WHERE id_user = u.id);

COMMIT;

-- =============================================================================
-- Maintenance & Monitoring
-- =============================================================================
-- 1. Schedule cleanup jobs (pg_cron recommended):
--    SELECT cron.schedule('cleanup-sessions', '0 * * * *', 'SELECT auth.cleanup_expired_sessions()');
--    SELECT cron.schedule('cleanup-oauth', '*/15 * * * *', 'SELECT auth.cleanup_expired_oauth_states()');
--
-- 2. Monitor table bloat and run VACUUM ANALYZE periodically
--
-- 3. For production, create read replica indexes CONCURRENTLY:
--    CREATE INDEX CONCURRENTLY IF NOT EXISTS ... ON auth.sessions ...
--
-- 4. Useful monitoring queries:
--    -- Active sessions per user
--    SELECT id_user, COUNT(*) FROM auth.sessions WHERE expires_at > now() GROUP BY 1;
--
--    -- Sessions expiring soon (next hour)
--    SELECT COUNT(*) FROM auth.sessions WHERE expires_at BETWEEN now() AND now() + INTERVAL '1 hour';
--
--    -- Suspended/pending users
--    SELECT COUNT(*), status FROM auth.users WHERE deleted_at IS NULL GROUP BY status;
-- =============================================================================
