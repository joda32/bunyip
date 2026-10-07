# Deploying into a restricted network

Offline VulnDB uses two machines:

- **Build machine** (Internet access): runs the Python updater, which builds
  `vulndb.sqlite`, and packages it as a signed bundle.
- **Offline machine** (restricted network): has only the static `vulndb` binary
  and the installed database. It verifies and installs bundles, then queries.

```text
 build machine                                     offline machine
 ─────────────                                     ───────────────
 vulndb-update build ──> vulndb.sqlite
 vulndb bundle create ─> vulndb-YYYY-MM-DD.tar.gz ──(removable media)──> vulndb bundle import
            ▲ signing key (stays here)                       ▲ public key (installed once)
```

## One-time setup

On the build machine:

```bash
bin/vulndb bundle keygen --key vulndb-signing.key --pub vulndb-signing.pub
```

- The private key (`vulndb-signing.key`, mode 0600) never leaves the build
  machine.
- Copy `vulndb-signing.pub` to the offline machine through a separate trusted
  channel, not in the same transfer as the bundles it will verify. Note the key
  ID printed at creation, and confirm it on the offline side.

On the offline machine, copy `bin/vulndb` (one static binary, no runtime
dependencies) and the public key. To see results inline in Nmap scans, also
copy `nse/vulndb.nse` (see README, "Inline in Nmap").

## Each update

On the build machine:

```bash
make real-db                                    # NVD + KEV + distribution advisories -> vulndb.sqlite
bin/vulndb --db vulndb.sqlite bundle create --key vulndb-signing.key \
    --out vulndb-$(date -u +%F).tar.gz
```

On the offline machine:

```bash
vulndb bundle verify vulndb-2026-10-07.tar.gz --pubkey vulndb-signing.pub     # optional dry run
vulndb --db /opt/vulndb/vulndb.sqlite bundle import vulndb-2026-10-07.tar.gz --pubkey vulndb-signing.pub
vulndb --db /opt/vulndb/vulndb.sqlite info                                   # data age, sources
```

## What import checks

Nothing replaces the installed database until every check passes:

1. **Layout.** The archive must contain exactly `manifest.json`, then
   optionally `manifest.sig`, then `vulndb.sqlite`, all regular files with
   exactly these names. Anything else (extra members, links, other paths,
   another order) is rejected. Nothing is written outside the target directory.
2. **Signature.** `manifest.sig` must be a valid Ed25519 signature of
   `manifest.json` by the trusted key. This is checked before the database is
   extracted. Unsigned bundles need `--allow-unsigned`.
3. **Content.** The database streams to a temporary file next to the target,
   and its size and SHA-256 must match the signed manifest.
4. **Usability.** The schema version must be one this binary supports,
   SQLite's `quick_check` must pass, and the database metadata must match the
   manifest.
5. **No rollback.** A bundle older than the installed database is refused
   unless `--allow-downgrade` is given, so an old, validly signed bundle cannot
   silently reintroduce stale data. Re-importing the installed version is
   verified, then reported as "nothing to do".

The installed database is then replaced atomically (rename). The previous one
is kept as `<db>.previous`.

## Sizes and times (2026-10-07, all sources, 4-core i5-6500T)

| | |
|---|---|
| Database | 835 MB (383k CVEs, 3.2M rules, 5 distributions) |
| Bundle | 140 MB (gzip) |
| Build (offline rebuild from cached feeds) | 336 s, 633 MB peak memory |
| `bundle create` | 18 s, 14 MB memory |
| `bundle verify` | 6 s |
| `bundle import` | 12 s, 19 MB memory |

Verified on real data:
- A bundle corrupted in transit is rejected ("flate: corrupt input"), with the
  installed database untouched.
- An older, validly signed bundle is refused as a rollback.

## Staleness

`vulndb info` reports the NVD data date and warns after 7 days. How old the
data is on the offline side depends only on how often bundles are built and
carried in.
