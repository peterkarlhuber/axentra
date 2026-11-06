# Backup and restore

An Axentra installation has three things to back up. Losing any one of them loses data.

| What | Contains | How |
|---|---|---|
| PostgreSQL database | All Axentra tables (users, tenants, records, keys, audit, ...) and your product tables | `pg_dump --format=custom`, plus continuous archiving if you need a small RPO |
| **Encryption keyring** (`security.master_keys_ref`) | The keys that decrypt values stored with `SecretBox` | Copy of the secret, stored separately from the dumps (password manager, KMS, offline) |
| File storage (storage module) | Uploaded files (`storage.local_path`, default `/var/lib/axentra/var/storage` in the image, or the S3 bucket) | Volume snapshot / file backup, or bucket versioning and replication |

Configuration files and `.env` (or your secret store) should be versioned or backed up too; they
are needed to start the restored system.

## File storage backup

The database holds the file rows (name, size, SHA-256, storage key); the backend holds the bytes.
Both must come from (about) the same point in time, and the database must not be newer:

1. Set `storage.deleted_object_retention_hours` to more than the time between the start of the
   database dump and the end of the file copy that follows it (for example `24` for a nightly
   dump followed by a file backup). The purge then keeps the object of a deleted or expired file
   that long, so a restored database still finds the objects of files deleted after the dump.
   Deleted files stay invisible to the API either way. With the default `0` an object deleted
   between the dump and the copy is lost for the restored row.
2. Dump the database first, then copy the file storage (`rsync -a` of `storage.local_path`, a
   volume snapshot, or an S3 bucket replica / versioned copy). Files uploaded after the dump end
   up as orphaned objects in the copy; that is harmless (see below).
3. Back up both together and keep the same number of generations.

After a restore, run `axentra storage verify` (add `--checksums` to also compare every object with
its stored SHA-256, which reads all objects):

```text
$ axentra storage verify
{"files_checked":1520,"missing":[],"corrupt":[],"retained_objects":3,"orphans":12,"truncated":false}
```

It prints a JSON report and exits with status 1 when an active file has no object (`missing`) or a
different content (`corrupt`), listing their ids. Orphans (objects without a row, e.g. uploads after the dump) and
retained objects of deleted files are reported, not errors; the next `axentra storage purge`
removes them (orphans at once, retained objects once the retention passed). `--limit N` checks only
the first N files for a quick drill.

**The keyring backup is mandatory.** Dumps contain ciphertexts and hashes, never keys. A restored
database without the keyring that was active when values were written cannot decrypt them. Back
up the keyring every time it changes (rotation adds a key), and keep old keys as long as any
backup may still be restored. Store dumps and the keyring in different places with different
access rights: one without the other is useless to an attacker.

## Database backup

```bash
# compose stack
docker compose -f docker-compose.single.yml exec -T db \
    pg_dump -U postgres --format=custom axentra > axentra-$(date -u +%Y%m%dT%H%M%SZ).dump

# any server (pg_dump major version >= server major version)
PGPASSWORD=... pg_dump --host db.internal --username postgres --format=custom --file axentra.dump axentra
```

- The custom format is compressed, restores selectively and in parallel (`pg_restore -j`).
- `pg_dump` takes a consistent snapshot while the API keeps running.
- Dump as a superuser or as a dedicated backup role with `BYPASSRLS`. Row-level security is
  forced on the protected tables, so `pg_dump` run as the owner or the application role fails
  with "query would be affected by row-level security policy" (verified). A least-privilege
  backup role: `CREATE ROLE axentra_backup LOGIN BYPASSRLS PASSWORD '...'; GRANT pg_read_all_data
  TO axentra_backup;` (PostgreSQL 14+). Never use `--enable-row-security` for backups: it would
  dump only the rows visible in an empty scope, i.e. none.
- Roles are global objects and not part of a database dump. Recreate them on the target server
  with `deploy/compose/initdb/01-roles.sql` (or keep a `pg_dumpall --globals-only` copy, which
  contains password hashes).
- Encrypt and copy dumps off the host. Keep several generations (for example 7 daily, 4 weekly,
  12 monthly).

## Restore

Restore into a **new** database, verify, then switch over. Never restore over the live database.

```bash
# 1. Roles exist on the target server (01-roles.sql); create an empty database owned by the owner role
createdb -U postgres --owner=axentra_owner axentra_restore

# 2. Restore; fail on the first error and keep it atomic
pg_restore -U postgres --dbname=axentra_restore --exit-on-error --single-transaction axentra.dump

# 3. Database-level grants are not part of a plain dump: re-apply them
psql -U postgres -d axentra_restore -c "REVOKE ALL ON DATABASE axentra_restore FROM PUBLIC" \
     -c "GRANT CONNECT, TEMPORARY ON DATABASE axentra_restore TO axentra_app"
```

In the compose stack, prefix the commands with `docker compose -f ... exec -T db` and pipe the
dump into `pg_restore` (`... pg_restore -U postgres --dbname=axentra_restore --exit-on-error
--single-transaction < axentra.dump`).

Table ownership, privileges, default privileges, row-level security flags and policies are part
of the dump and are restored with it.

Switch over:

1. Stop the API (`docker compose ... stop api`).
2. Either rename (`ALTER DATABASE axentra RENAME TO axentra_old;` then
   `ALTER DATABASE axentra_restore RENAME TO axentra;`, re-applying the grants of step 3 under the
   new name) or point `AXENTRA_DATABASE_URL` at the restored database.
3. Make sure the keyring that matches the backup is configured (the active keyring plus every
   older key used when the backup was taken).
4. Run `axentra migrate --grant-runtime-role axentra_app` as the owner role (applies migrations
   newer than the backup, verifies checksums of the rest, re-applies the runtime role's grants),
   then start the API.
5. Restore the file storage copy taken right after the database dump, then run
   `axentra storage verify` (see "File storage backup").

## Verify a restore

Do this after every restore and regularly as a drill:

- `axentra migrate --status`: every migration `applied`, `checksum_ok`.
- `GET /v1/health/ready` returns `ok`; the API started, which also proves the application role does
  not bypass RLS.
- Row-level security survived:
  `SELECT relname FROM pg_class WHERE relname LIKE 'axentra_%' AND relkind = 'r' AND relrowsecurity AND relforcerowsecurity;`
  lists products, product_members, tenants, memberships, invitations, roles, api_keys,
  audit_events and records; `SELECT count(*) FROM pg_policies;` matches the source.
- Row counts of key tables match the source at backup time.
- A platform admin can log in, a known record can be read, an API key still authenticates.
- `axentra storage verify` reports no missing or corrupt files.
- Values encrypted with `SecretBox` decrypt (once modules store them).

The automated test `tests/integration/test_backup_restore.py` performs this procedure on every CI
run: it seeds data through the API, dumps with `pg_dump --format=custom`, restores into a new
database with `pg_restore --exit-on-error --single-transaction`, compares row counts, RLS flags,
policies and table owners, checks that no migration is pending, and runs the application against
the restored database (login, record read and write, API key still confined to its tenant). The
same file also restores database and local file storage together
(`test_database_and_file_storage_restore_together`): it deletes and uploads files between the dump
and the file copy, restores both, and checks that `storage verify` passes, every restored file
downloads with its original content and the purge removes the orphan.

## RPO and RTO

- **RPO** (data you can lose) with nightly dumps alone is up to 24 hours. For minutes or less, add
  WAL archiving and point-in-time recovery (pgBackRest, WAL-G, Barman, or a managed PostgreSQL
  service) and keep the dumps as an independent second copy.
- **RTO** (time to restore) is dominated by `pg_restore` (use `-j <cores>` for large databases,
  without `--single-transaction`), file storage copy, and the verification steps. Measure it in a
  drill and write the number down.
- Migrations are forward-only: rolling back a release means restoring the backup taken right
  before the migration, so always back up immediately before an upgrade.

## Deleting data and backups

Deleting a tenant removes its rows from the live database, not from existing backups. Define a
backup retention that matches your deletion obligations, and document how restores handle data
deleted after the backup was taken (for example by replaying erasure requests).
