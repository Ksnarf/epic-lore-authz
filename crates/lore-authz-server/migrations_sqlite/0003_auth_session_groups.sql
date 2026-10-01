-- SQLite dialect of migrations/0003_auth_session_groups.sql. Read that file
-- first: it carries the full rationale (why this is a login-time snapshot on
-- auth_sessions rather than a durable attribute, and why it is not the
-- existing groups/group_members tables), deliberately not duplicated here.
--
-- `ALTER TABLE ... ADD COLUMN` has no `IF NOT EXISTS` form in SQLite. Safe
-- regardless, same reasoning as 0002's `idp` column: sqlx's migrator records
-- which migrations have already run and never re-runs this file, so this
-- executes exactly once per database.
ALTER TABLE auth_sessions ADD COLUMN groups_json TEXT;
