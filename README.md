# SQLite authorizer xfer bypass PoC

SQLite authorizer bypass in the xfer optimization.

## Claim

SQLite 3.53.1 can bypass an application's `sqlite3_set_authorizer()` read denial when attacker-controlled SQL reaches:

```sql
INSERT INTO loot SELECT * FROM secret;
```

The optimized xfer path copies source table records without invoking the expected source-table `SQLITE_SELECT` / `SQLITE_READ` authorization checks. A direct read from `secret` is denied, but the same rows can be copied into attacker-readable storage and read from there.

The vendored trunk snapshot contains an added authorizer block in `xferOptimization()` and blocks the PoC.

## Run

```bash
bash validate.sh
```

Expected result:

```text
mode: breakin
old-status: 3
trunk-status: 0
RESULT=VULNERABLE_REMOTE_ADMIN_BREAKIN
RESULT=SAFE_NO_ADMIN_BREAKIN
validation: PASS
```

Run all variants:

```bash
bash validate.sh all
```

## What the PoC proves

The PoC starts a loopback victim service that:

- accepts SQL-like requests over TCP,
- installs an authorizer that denies `SQLITE_READ` on table `secret`,
- stores synthetic sensitive values in `secret`,
- exposes an `ADMIN <token>` endpoint outside SQL.

Against SQLite 3.53.1:

- direct read of the admin token is blocked,
- wrong admin token is rejected,
- `INSERT INTO loot SELECT * FROM secret` succeeds,
- attacker reads `loot`,
- attacker obtains the admin session token,
- attacker calls the admin endpoint with the stolen token,
- endpoint grants admin access.

Against the vendored trunk snapshot:

- direct read is still blocked,
- the xfer copy is denied,
- no secret is copied,
- admin access is not granted.

## Vendored SQLite snapshots

- Vulnerable: SQLite 3.53.1, source id `2026-05-05 10:34:17 c88b22011a54b4f6fbd149e9f8e4de77658ce58143a1af0e3785e4e6475127e9`
- Fixed: SQLite trunk 3.54.0 snapshot, source id `2026-05-21 15:14:35 9ac4a33a2932d353c4871fd8e09c10addf827f1fc3fc9380037d738cf2cd0353`

## Files

- `poc/sqlite_authorizer_xfer_poc.c`: remote victim and attacker PoC
- `validate.sh`: reproducible validator
- `evidence/remote-admin-breakin-validation.txt`: captured high-impact proof
- `evidence/remote-xfer-exfil-validation.txt`: direct xfer exfil proof
- `evidence/remote-vacuum-exfil-validation.txt`: related `VACUUM INTO` export proof
- `third_party/`: exact SQLite amalgamations used for validation

## Notes

This is not a default remote exploit against every SQLite user. It affects applications that use SQLite as a sandboxed SQL execution engine, rely on `sqlite3_set_authorizer()` as the permission boundary, deny reads from sensitive tables or columns, and still allow a path where attacker SQL can copy/export data into readable storage.

All secrets in this repo are synthetic PoC values.
