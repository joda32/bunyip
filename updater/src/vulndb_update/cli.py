"""vulndb-update command line."""

import argparse
import sys
import time
from pathlib import Path

from . import __version__, build, fetch, kev, jsonstream

# src/vulndb_update/cli.py -> repository root is three levels up.
_REPO_SCHEMA = Path(__file__).resolve().parents[3] / "schema" / "schema.sql"


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
    b.add_argument("--allow-small", action="store_true",
                   help="skip the completeness floors (for tests and partial builds)")
    b.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    log = (lambda *a, **k: None) if args.quiet else (lambda *a, **k: print(*a, **k, flush=True))
    try:
        return _build(args, log)
    except (fetch.FetchError, build.BuildError, kev.KEVError, jsonstream.StreamError,
            OSError, ValueError) as e:
        print(f"vulndb-update: {e}", file=sys.stderr)
        return 1


def _build(args, log) -> int:
    if not args.schema.is_file():
        raise build.BuildError(f"schema file not found: {args.schema} (use --schema)")
    start = time.monotonic()
    if args.offline_from:
        log(f"Using local source files in {args.offline_from}")
        feeds = fetch.local_feeds(args.offline_from)
        kev_path = fetch.local_kev(args.offline_from)
    else:
        log(f"Syncing NVD feeds into {args.cache}")
        feeds = fetch.sync_nvd(args.cache, fetch.feed_names(), log)
        kev_path = fetch.sync_kev(args.cache, log)

    log(f"Building {args.out}")
    stats = build.build(args.out, args.schema.read_text(encoding="utf-8"), feeds, kev_path,
                        allow_small=args.allow_small, log=log)
    log(f"Done in {time.monotonic() - start:.0f}s: {stats.loaded} CVEs loaded, "
        f"{stats.replaced} updated by overlay, {stats.unchanged} unchanged, "
        f"{stats.rejected} rejected, {len(stats.skipped_rules)} unparseable rules skipped")
    for msg in stats.skipped_rules[:10]:
        log(f"  skipped: {msg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
