-- Axentra database roles, run once by the postgres image on first initialization
-- (/docker-entrypoint-initdb.d, as the superuser, connected to $POSTGRES_DB).
--
-- axentra_owner  owns the schema and runs migrations (`axentra migrate`).
-- axentra_app    is what the API uses at runtime: no superuser, no BYPASSRLS, no DDL, only
--                SELECT/INSERT/UPDATE/DELETE on tables created by axentra_owner. Row-level
--                security therefore applies to every query of the API (Axentra refuses to start in
--                production with a role that bypasses RLS).
--
-- Passwords come from the container environment (AXENTRA_DB_OWNER_PASSWORD, AXENTRA_DB_APP_PASSWORD),
-- read with psql's \getenv (psql >= 15). Use URL-safe values (e.g. `openssl rand -hex 24`), since they
-- are also embedded in connection URLs. For an existing server, run the same statements manually.

\set ON_ERROR_STOP on
\getenv owner_password AXENTRA_DB_OWNER_PASSWORD
\getenv app_password AXENTRA_DB_APP_PASSWORD

\if :{?owner_password}
\else
DO $$ BEGIN RAISE EXCEPTION 'AXENTRA_DB_OWNER_PASSWORD is not set'; END $$;
\endif
\if :{?app_password}
\else
DO $$ BEGIN RAISE EXCEPTION 'AXENTRA_DB_APP_PASSWORD is not set'; END $$;
\endif

SELECT current_database() AS dbname \gset

CREATE ROLE axentra_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'owner_password';
CREATE ROLE axentra_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password';

-- The owner role owns the database and therefore (PostgreSQL 15+) the public schema.
ALTER DATABASE :"dbname" OWNER TO axentra_owner;
ALTER SCHEMA public OWNER TO axentra_owner;
REVOKE ALL ON DATABASE :"dbname" FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"dbname" TO axentra_app;
GRANT USAGE ON SCHEMA public TO axentra_app;

-- Everything the owner creates later (migrations of Axentra and of product namespaces) is usable,
-- but not alterable, by the application role.
ALTER DEFAULT PRIVILEGES FOR ROLE axentra_owner IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO axentra_app;
ALTER DEFAULT PRIVILEGES FOR ROLE axentra_owner IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO axentra_app;
ALTER DEFAULT PRIVILEGES FOR ROLE axentra_owner IN SCHEMA public
    GRANT EXECUTE ON FUNCTIONS TO axentra_app;
