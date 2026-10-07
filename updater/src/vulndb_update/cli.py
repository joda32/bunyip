"""vulndb-update command line."""

import argparse
import sys
import time
from pathlib import Path

from . import __version__, aliases, build, fetch, kev, jsonstream, osv

# src/vulndb_update/cli.py -> repository root is three levels up.
_REPO = Path(__file__).resolve().parents[3]
_REPO_SCHEMA = _REPO / "schema" / "schema.sql"
_REPO_ALIASES = _REPO / "data" / "aliases.json"
_REPO_PACKAGES = _REPO / "data" / "distro_packages.json"
_REPO_RELEASES = _REPO / "data" / "distro_releases.json"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="vulndb-update", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    b = sub.add_parser("build", help="build a fresh vulndb.sqlite from NVD + CISA KEV")
    b.add_argument("--out", required=True, type=Path, help="database file to create or replace")
    src = b.add_mutually_exclusive_group()
    src.add_argument("--cache", type=Path, default=Path(".cache/feeds"),
                     help="download cache; unchanged feeds are not re-downloaded (default .cache/feeds)")
    src.add_argument("--offline-from", type=Path,
                     help="build from already-downloaded files in this directory, no network access")
    b.add_argument("--schema", type=Path, default=_REPO_SCHEMA,
                   help="schema.sql (default: the repository's schema/schema.sql)")
    b.add_argument("--aliases", type=Path, default=_REPO_ALIASES,
                   help="curated aliases file (default: the repository's data/aliases.json)")
    b.add_argument("--distro", action="append", choices=sorted(osv.DISTROS),
                   help="distribution advisories to include (default: all supported; repeatable)")
    b.add_argument("--no-distro", action="store_true", help="build without distribution advisories")
    b.add_argument("--distro-packages", type=Path, default=_REPO_PACKAGES,
                   help="curated CPE -> distro package map (default: data/distro_packages.json)")
    b.add_argument("--distro-releases", type=Path, default=_REPO_RELEASES,
                   help="curated release lifecycle (default: data/distro_releases.json)")
    b.add_argument("--allow-small", action="store_true",
                   help="skip the completeness floors (for tests and partial builds)")
    b.add_argument("--quiet", action="store_true")

    r = sub.add_parser("review-aliases", help="propose aliases for human review from Nmap's service probes")
    r.add_argument("--db", required=True, type=Path, help="a built vulndb.sqlite")
    r.add_argument("--nmap-probes", type=Path, default=Path("/usr/share/nmap/nmap-service-probes"))
    r.add_argument("--aliases", type=Path, default=_REPO_ALIASES)
    args = p.parse_args(argv)

    log = (lambda *a, **k: None) if getattr(args, "quiet", False) else (lambda *a, **k: print(*a, **k, flush=True))
    try:
        if args.command == "review-aliases":
            return _review(args)
        return _build(args, log)
    except (fetch.FetchError, build.BuildError, kev.KEVError, jsonstream.StreamError,
            aliases.AliasError, OSError, ValueError) as e:
        print(f"vulndb-update: {e}", file=sys.stderr)
        return 1


def _build(args, log) -> int:
    if not args.schema.is_file():
        raise build.BuildError(f"schema file not found: {args.schema} (use --schema)")
    alias_rows, _ = aliases.load(args.aliases)
    package_map = osv.load_package_map(args.distro_packages)
    releases = osv.load_releases(args.distro_releases)
    wanted = [] if args.no_distro else (args.distro or sorted(osv.DISTROS))
    start = time.monotonic()
    distros = []
    if args.offline_from:
        log(f"Using local source files in {args.offline_from}")
        feeds = fetch.local_feeds(args.offline_from)
        kev_path = fetch.local_kev(args.offline_from)
        for name in wanted:
            d = osv.DISTROS[name]
            export = fetch.local_osv(args.offline_from, d.ecosystem)
            if export is None:
                raise fetch.FetchError(f"no OSV {d.ecosystem} export in {args.offline_from} (use --no-distro)")
            distros.append(build.DistroInput(d, export))
    else:
        log(f"Syncing NVD feeds into {args.cache}")
        feeds = fetch.sync_nvd(args.cache, fetch.feed_names(), log)
        kev_path = fetch.sync_kev(args.cache, log)
        for name in wanted:
            d = osv.DISTROS[name]
            distros.append(build.DistroInput(d, fetch.sync_osv(args.cache, d.ecosystem, log)))

    log(f"Building {args.out}")
    stats = build.build(args.out, args.schema.read_text(encoding="utf-8"), feeds, kev_path,
                        allow_small=args.allow_small, log=log, alias_rows=alias_rows,
                        distros=distros, package_map=package_map, releases=releases)
    log(f"Done in {time.monotonic() - start:.0f}s: {stats.loaded} CVEs loaded, "
        f"{stats.replaced} updated by overlay, {stats.unchanged} unchanged, "
        f"{stats.rejected} rejected, {len(stats.skipped_rules)} unparseable rules skipped")
    for msg in stats.skipped_rules[:10]:
        log(f"  skipped: {msg}")
    for prefix in stats.aliases_without_rules:
        log(f"  alias target without NVD rules: {prefix}")
    for p in stats.unmapped_packages:
        log(f"  mapped package with no advisories: {p}")
    return 0


def _review(args) -> int:
    cands = aliases.review(args.db, args.nmap_probes, args.aliases)
    print(f"{len(cands)} alias candidates for review (curated and rejected identities excluded).")
    print("Add genuine renames/acquisitions to data/aliases.json; record false matches under 'rejected'.\n")
    for c in cands:
        print(f"[{c.kind}] {c.observed}  (Nmap: {c.nmap_product!r})")
        print(f"    NVD has: {'; '.join(c.targets)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
