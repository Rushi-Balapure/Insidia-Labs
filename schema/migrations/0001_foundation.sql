-- Phase 0 foundation. Dev role passwords below are for local compose only.
-- Production sets passwords outside this migration and refuses the dev master key.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'insidia_owner') THEN
    CREATE ROLE insidia_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_api') THEN
    CREATE ROLE app_api LOGIN PASSWORD 'app_api_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_worker') THEN
    CREATE ROLE app_worker LOGIN PASSWORD 'app_worker_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_reports') THEN
    CREATE ROLE app_reports NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_audit') THEN
    CREATE ROLE app_audit LOGIN PASSWORD 'app_audit_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_keys') THEN
    CREATE ROLE app_keys LOGIN PASSWORD 'app_keys_dev_only' NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_admin_read') THEN
    CREATE ROLE app_admin_read NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_admin_write') THEN
    CREATE ROLE app_admin_write NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'celery_results') THEN
    CREATE ROLE celery_results LOGIN PASSWORD 'celery_results_dev_only'
      NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_readonly_ops') THEN
    CREATE ROLE app_readonly_ops NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

CREATE TABLE orgs (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  name_enc bytea NOT NULL,
  region text NOT NULL,
  plan text NOT NULL DEFAULT 'trial',
  retention_days int NOT NULL DEFAULT 180,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'deleting')),
  trial_started_at timestamptz NOT NULL DEFAULT now(),
  trial_scans_used int NOT NULL DEFAULT 0,
  converted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE org_keys (
  org_id uuid NOT NULL REFERENCES orgs (id),
  purpose text NOT NULL CHECK (purpose IN ('data', 'secrets', 'blind_index')),
  key_version int NOT NULL,
  wrapped_key bytea NOT NULL,
  kms_key_ref text NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'decrypt_only', 'destroyed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, purpose, key_version)
);

CREATE TABLE projects (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  org_id uuid NOT NULL REFERENCES orgs (id),
  name_enc bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_events (
  seq bigint GENERATED ALWAYS AS IDENTITY,
  org_id uuid NOT NULL REFERENCES orgs (id),
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'api_key', 'runner', 'system', 'staff')),
  actor_id uuid,
  action text NOT NULL,
  target_type text,
  target_id uuid,
  ip_enc bytea,
  metadata_enc bytea,
  key_version int NOT NULL,
  prev_hash bytea NOT NULL,
  row_hash bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, seq)
);

CREATE TABLE tenant_pings (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES orgs (id),
  project_id uuid NOT NULL REFERENCES projects (id),
  scan_id uuid NOT NULL,
  payload_enc bytea NOT NULL,
  key_version int NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE OR REPLACE FUNCTION reject_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

CREATE TRIGGER audit_events_no_row_mutation
  BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_mutation();

-- A custom GUC resets to '' at transaction end, and ''::uuid is an error.
-- NULLIF makes a missing or blank tenant match no rows.
CREATE FUNCTION current_org_id() RETURNS uuid
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('app.org_id', true), '')::uuid
$$;

ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects FORCE ROW LEVEL SECURITY;
ALTER TABLE org_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_pings ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_pings FORCE ROW LEVEL SECURITY;

-- orgs is the tenant root. Reads require the session org. Inserts are the
-- signup bootstrap and are granted only to app_api.
ALTER TABLE orgs ENABLE ROW LEVEL SECURITY;
ALTER TABLE orgs FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_select ON orgs
  FOR SELECT USING (id = current_org_id());
CREATE POLICY tenant_update ON orgs
  FOR UPDATE USING (id = current_org_id())
  WITH CHECK (id = current_org_id());
CREATE POLICY signup_insert ON orgs
  FOR INSERT WITH CHECK (true);

CREATE POLICY tenant_isolation ON projects
  USING (org_id = current_org_id())
  WITH CHECK (org_id = current_org_id());
CREATE POLICY tenant_isolation ON org_keys
  USING (org_id = current_org_id())
  WITH CHECK (org_id = current_org_id());
CREATE POLICY tenant_isolation ON audit_events
  USING (org_id = current_org_id())
  WITH CHECK (org_id = current_org_id());
CREATE POLICY tenant_isolation ON tenant_pings
  USING (org_id = current_org_id())
  WITH CHECK (org_id = current_org_id());

REVOKE ALL ON orgs, org_keys, projects, audit_events, tenant_pings FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON orgs TO app_api;
GRANT SELECT, INSERT ON projects TO app_api;
GRANT SELECT ON tenant_pings TO app_api;
GRANT SELECT, INSERT ON projects TO app_worker;
GRANT SELECT, INSERT ON tenant_pings TO app_worker;
GRANT SELECT, INSERT ON org_keys TO app_keys;
GRANT INSERT, SELECT ON audit_events TO app_audit;
GRANT USAGE ON SEQUENCE audit_events_seq_seq TO app_audit;
GRANT CREATE ON SCHEMA public TO celery_results;

REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events FROM app_api, app_worker, app_audit, app_keys;
