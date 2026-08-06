#!/usr/bin/env python3
"""buzzcut — find and cut credentials left behind in Claude Code transcripts.

  buzzcut scan            what is in ~/.claude/projects (read-only)
  buzzcut check --yes     which of those keys still work (network)
  buzzcut clean           cut them out, with a mandatory backup
"""

import argparse
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cleaner import clean_file                      # noqa: E402
from detect import find_secrets                     # noqa: E402
from liveness import DEAD, LIVE, MANUAL, check_key  # noqa: E402
from scanner import (DEFAULT_ROOT, MIN_LINE, mask, maybe_secret,  # noqa: E402
                     project_of, scan, shorten_projects, transcript_paths)

KIND_LABEL = {
    "openai": "OpenAI", "anthropic": "Anthropic", "github": "GitHub PAT",
    "aws": "AWS", "google": "Google API", "slack": "Slack",
    "telegram": "Telegram", "private_key": "private key",
    "jwt": "JWT", "url_credentials": "URL credentials", "env_secret": "ENV secret",
}


def _human_bytes(n):
    return f"{n / 1e9:.2f} GB" if n >= 1e9 else f"{n / 1e6:.0f} MB"


def _progress(done, total):
    """Полоса в stderr. Под Claude Code вывод команды не стримится — там её
    просто не видно, и это нормально: она для запуска из терминала, где
    двухминутная тишина выглядит как зависание."""
    if not sys.stderr.isatty():
        return
    if done % 50 and done != total:
        return
    sys.stderr.write(f"\r  scanning… {done}/{total} · {100 * done // total}%")
    if done == total:
        sys.stderr.write("\r" + " " * 40 + "\r")
    sys.stderr.flush()


def cmd_scan(args):
    r = scan(args.root, project=args.project, on_progress=_progress)
    scope = f"{args.root}  ·  filter: {args.project}" if args.project else args.root
    print()
    print(f"  buzzcut — {scope}")
    print(f"  {r['files']} files · {_human_bytes(r['bytes'])}")
    if not args.project:
        print("  (every Claude Code project, not just this one — "
              "narrow with: buzzcut scan --project NAME)")
    print()
    if not r["occurrences"]:
        print("  No secrets found.\n")
        return 0

    print(f"  FOUND    {r['unique']} unique · {r['occurrences']} occurrences · "
          f"{r['files_hit']} files")
    print()
    print("  BY PROJECT")
    top = r["by_project"][:10]
    labels = shorten_projects([p for p, _, _ in top], width=46)
    for proj, occ, uniq in top:
        print(f"    {labels[proj]:<46}{uniq:>4} keys {occ:>6} occ.")
    print()
    print("  BY TYPE")
    for kind, occ, uniq in r["by_kind"]:
        print(f"    {KIND_LABEL.get(kind, kind):<18}{uniq:>4} uniq. {occ:>6} occ.")
    print()
    print("  buzzcut check --yes    which of these still work")
    print("  buzzcut clean          cut them out of the files")
    print()
    return 0


def _collect_unique(root, project=None):
    """{digest: (kind, value, project)} — значения держим только в памяти."""
    out = {}
    paths = transcript_paths(root)
    if project:
        paths = [p for p in paths if project in project_of(p, root)]
    for path in paths:
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        proj = project_of(path, root)
        with fh:
            for line in fh:
                if len(line) < MIN_LINE or not maybe_secret(line):
                    continue
                for f in find_secrets(line):
                    d = hashlib.sha256(f.value.encode()).hexdigest()[:16]
                    out.setdefault(d, (f.kind, f.value, proj))
    return out


def cmd_check(args):
    found = _collect_unique(args.root, project=args.project)
    if not found:
        print("\n  No secrets found.\n")
        return 0

    auto = [(k, v, p) for k, v, p in found.values() if check_key(k, "") != MANUAL]
    print(f"\n  {len(found)} unique keys found.")
    print(f"  Checkable automatically: {len(auto)} — the rest need your judgement.")
    print()
    if not args.yes:
        print("  This sends each key to its own provider over a read-only")
        print("  endpoint. Keys go nowhere else.")
        print("  Re-run with --yes if that is what you want.\n")
        return 1

    live, dead, manual = [], [], []
    for kind, value, proj in found.values():
        verdict = check_key(kind, value)
        row = (KIND_LABEL.get(kind, kind), mask(value), proj)
        (live if verdict == LIVE else dead if verdict == DEAD else manual).append(row)

    if live:
        print("  LIVE — rotate now")
        for k, m, p in live:
            print(f"    {k:<16}{m:<18}{p}")
        print()
    if dead:
        print(f"  DEAD — {len(dead)}, already rotated, just clean them out\n")
    if manual:
        print(f"  YOUR CALL — {len(manual)}")
        for k, m, p in manual[:8]:
            print(f"    {k:<16}{m:<18}{p}")
        if len(manual) > 8:
            print(f"    …and {len(manual) - 8} more")
        print()
    print(f"  TOTAL   {len(live)} live · {len(dead)} dead · {len(manual)} to judge\n")
    return 0


def cmd_clean(args):
    paths = transcript_paths(args.root)
    if args.project:
        paths = [p for p in paths if args.project in project_of(p, args.root)]

    backup = args.backup or os.path.expanduser("~/.claude/projects.buzzcut-backup")
    total, touched = 0, 0
    for path in paths:
        n = clean_file(path, backup_dir=backup, dry_run=args.dry_run)
        if n:
            total += n
            touched += 1

    verb = "would cut" if args.dry_run else "cut"
    print(f"\n  {verb} {total} occurrences in {touched} files")
    if args.dry_run:
        print("  Dry run. Drop --dry-run to apply.\n")
    elif total:
        print(f"  Backup: {backup}\n")
    else:
        print()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="buzzcut", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=DEFAULT_ROOT)
    sub = ap.add_subparsers(dest="cmd")

    PROJECT_HELP = "limit to projects whose name contains this substring"

    s = sub.add_parser("scan", help="report what is there; changes nothing")
    s.add_argument("--project", help=PROJECT_HELP)
    s.set_defaults(fn=cmd_scan)

    c = sub.add_parser("check", help="which keys still work (makes network calls)")
    c.add_argument("--yes", action="store_true", help="consent to the network calls")
    c.add_argument("--project", help=PROJECT_HELP)
    c.set_defaults(fn=cmd_check)

    cl = sub.add_parser("clean", help="cut secrets out of the transcripts")
    cl.add_argument("--dry-run", action="store_true")
    cl.add_argument("--project", help=PROJECT_HELP)
    cl.add_argument("--backup", help="where to put the backup")
    cl.set_defaults(fn=cmd_clean)

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
