-- DN Platform — Authentication & per-app access control migration
-- Run this in Supabase SQL Editor on the DN project.
-- Safe to re-run: uses IF NOT EXISTS / CREATE OR REPLACE / DROP POLICY IF EXISTS.
--
-- After running, set the first admin manually:
--   UPDATE profiles SET is_admin = true WHERE email = 'philip.korf@digitatanetworks.com';

-- =============================================================
-- 1. profiles table — mirrors auth.users with app-specific fields
-- =============================================================
CREATE TABLE IF NOT EXISTS profiles (
  id          uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email       text UNIQUE NOT NULL,
  full_name   text,
  avatar_url  text,
  provider    text,          -- 'google' | (later) 'azure'
  is_admin    boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS profiles_email_idx ON profiles(email);

-- Auto-create profile row whenever a new auth user signs up.
-- Pulls full_name + avatar_url from provider metadata if available.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
  INSERT INTO public.profiles (id, email, full_name, avatar_url, provider)
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(
      NEW.raw_user_meta_data->>'full_name',
      NEW.raw_user_meta_data->>'name',
      split_part(NEW.email, '@', 1)
    ),
    NEW.raw_user_meta_data->>'avatar_url',
    COALESCE(NEW.raw_app_meta_data->>'provider', 'unknown')
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- =============================================================
-- 2. Extend requests with creator_user_id FK
-- =============================================================
-- Keep existing submitted_by (free-text name) for backwards compat
-- but add a real FK so RLS can key off user identity.
ALTER TABLE requests
  ADD COLUMN IF NOT EXISTS creator_user_id uuid REFERENCES profiles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS requests_creator_user_id_idx ON requests(creator_user_id);

-- =============================================================
-- 3. app_access — per-app user grants (the access control list)
-- =============================================================
CREATE TABLE IF NOT EXISTS app_access (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  request_id   uuid NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
  user_id      uuid NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  granted_by   uuid REFERENCES profiles(id) ON DELETE SET NULL,
  granted_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (request_id, user_id)
);

CREATE INDEX IF NOT EXISTS app_access_user_idx    ON app_access(user_id);
CREATE INDEX IF NOT EXISTS app_access_request_idx ON app_access(request_id);

-- =============================================================
-- 4. Helper: is_admin(uid) — used by RLS policies
-- =============================================================
CREATE OR REPLACE FUNCTION public.is_admin(uid uuid)
RETURNS boolean AS $$
  SELECT COALESCE((SELECT is_admin FROM public.profiles WHERE id = uid), false);
$$ LANGUAGE sql STABLE SECURITY DEFINER;

-- =============================================================
-- 5. Enable RLS + policies
-- =============================================================

-- profiles -----------------------------------------------------
ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "profiles_select_self_or_admin" ON profiles;
CREATE POLICY "profiles_select_self_or_admin" ON profiles
  FOR SELECT USING (
    auth.uid() = id OR public.is_admin(auth.uid())
  );

DROP POLICY IF EXISTS "profiles_select_for_grants" ON profiles;
-- Admins can also see all profiles so they can search by email when granting access.
-- Non-admins can see profiles they share an app_access row with (so creators see who they granted to).
CREATE POLICY "profiles_select_for_grants" ON profiles
  FOR SELECT USING (
    public.is_admin(auth.uid())
    OR id IN (
      SELECT user_id FROM app_access
      WHERE request_id IN (SELECT id FROM requests WHERE creator_user_id = auth.uid())
    )
  );

DROP POLICY IF EXISTS "profiles_update_self" ON profiles;
CREATE POLICY "profiles_update_self" ON profiles
  FOR UPDATE USING (auth.uid() = id);

DROP POLICY IF EXISTS "profiles_admin_update" ON profiles;
CREATE POLICY "profiles_admin_update" ON profiles
  FOR UPDATE USING (public.is_admin(auth.uid()));

-- requests -----------------------------------------------------
ALTER TABLE requests ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "requests_select_creator_or_granted_or_admin" ON requests;
CREATE POLICY "requests_select_creator_or_granted_or_admin" ON requests
  FOR SELECT USING (
    creator_user_id = auth.uid()
    OR public.is_admin(auth.uid())
    OR id IN (SELECT request_id FROM app_access WHERE user_id = auth.uid())
  );

DROP POLICY IF EXISTS "requests_insert_authenticated" ON requests;
CREATE POLICY "requests_insert_authenticated" ON requests
  FOR INSERT WITH CHECK (
    auth.uid() IS NOT NULL
    AND creator_user_id = auth.uid()
  );

DROP POLICY IF EXISTS "requests_update_creator_or_admin" ON requests;
CREATE POLICY "requests_update_creator_or_admin" ON requests
  FOR UPDATE USING (
    creator_user_id = auth.uid()
    OR public.is_admin(auth.uid())
  );

DROP POLICY IF EXISTS "requests_delete_admin" ON requests;
CREATE POLICY "requests_delete_admin" ON requests
  FOR DELETE USING (public.is_admin(auth.uid()));

-- app_access ---------------------------------------------------
ALTER TABLE app_access ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "app_access_select_relevant" ON app_access;
CREATE POLICY "app_access_select_relevant" ON app_access
  FOR SELECT USING (
    user_id = auth.uid()                                       -- I can see my own grants
    OR public.is_admin(auth.uid())                             -- admins see all
    OR request_id IN (                                         -- creators see grants on their apps
      SELECT id FROM requests WHERE creator_user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS "app_access_insert_admin" ON app_access;
CREATE POLICY "app_access_insert_admin" ON app_access
  FOR INSERT WITH CHECK (public.is_admin(auth.uid()));

DROP POLICY IF EXISTS "app_access_delete_admin" ON app_access;
CREATE POLICY "app_access_delete_admin" ON app_access
  FOR DELETE USING (public.is_admin(auth.uid()));

-- activity_log -------------------------------------------------
-- Keep existing semantics (any signed-in user can append to their own actions).
ALTER TABLE activity_log ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "activity_log_select_authenticated" ON activity_log;
CREATE POLICY "activity_log_select_authenticated" ON activity_log
  FOR SELECT USING (auth.uid() IS NOT NULL);

DROP POLICY IF EXISTS "activity_log_insert_authenticated" ON activity_log;
CREATE POLICY "activity_log_insert_authenticated" ON activity_log
  FOR INSERT WITH CHECK (auth.uid() IS NOT NULL);

-- =============================================================
-- 6. Optional one-shot: backfill creator_user_id for existing requests
-- =============================================================
-- After everyone has signed in at least once, run this to link historic
-- requests to the profile whose email matches submitted_by_email (if you
-- have that), or by lower(full_name) match as a best effort:
--
--   UPDATE requests r
--   SET creator_user_id = p.id
--   FROM profiles p
--   WHERE r.creator_user_id IS NULL
--     AND lower(trim(r.submitted_by)) = lower(trim(p.full_name));
--
-- Leave commented until manually reviewed.

-- =============================================================
-- 7. Set the first admin (uncomment + edit before running)
-- =============================================================
-- UPDATE profiles SET is_admin = true WHERE email = 'philip.korf@digitatanetworks.com';

-- END OF MIGRATION
