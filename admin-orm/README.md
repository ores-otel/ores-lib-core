# Admin ORM boundary

This package is the named administrative database surface owned by
`ores-lib-core`. Admin API and web servers compile it from the same immutable
revision selected by Zed.

The web server receives only `AdminReadContext`, which requires PostgreSQL
`transaction_read_only=on`. The API receives `AdminWriteContext`, which
rejects a read-only credential. Neither context exposes its SeaORM connection,
and consumers cannot submit arbitrary SQL or run migrations.

The adapter pins the exact PostgreSQL host, database, and role, requires
`sslmode=verify-full`, rejects privileged or DDL-capable runtime roles, and
bounds pools and timeouts. Idempotency binds the complete actor/session/action
payload; accepted operations and their audit outbox event commit together.
