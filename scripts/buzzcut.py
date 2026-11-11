#!/usr/bin/env python3
"""buzzcut — find and cut API keys AI coding agents left in their logs.

Reads Claude Code (~/.claude/projects) and Codex (~/.codex) logs. Codex is
cleaned with same-length masks, only while no process holds its files.

  buzzcut scan            what is in the logs (read-only)
  buzzcut check --yes     which of those keys still work (network)
  buzzcut clean           cut them out, with a mandatory backup
"""

import argparse
import hashlib
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cleaner import clean_file, clean_sqlite        # noqa: E402
from detect import find_secrets                     # noqa: E402
from liveness import DEAD, LIVE, MANUAL, check_key  # noqa: E402
from scanner import (AGENT_LABEL, HOME, MIN_LINE, codex_session_id, log_files, mask,  # noqa: E402
                     maybe_secret, read_lines, scan, shorten_projects)

KIND_LABEL = {
    "openai": "OpenAI", "anthropic": "Anthropic", "github": "GitHub PAT",
    "aws": "AWS", "google": "Google API", "slack": "Slack",
    "telegram": "Telegram", "private_key": "private key",
    "jwt": "JWT", "url_credentials": "URL credentials", "env_secret": "ENV secret",
}


def _human_bytes(n):
    return f"{n / 1e9:.2f} GB" if n >= 1e9 else f"{n / 1e6:.0f} MB"


def _progress(done, total, stream=None):
    """Полоса в stderr. Под Claude Code вывод команды не стримится — там её
    просто не видно, и это нормально: она для запуска из терминала, где
    двухминутная тишина выглядит как зависание.

    `stream` — шов для тестов: подменять глобальный `sys.stderr` нельзя,
    pytest переустанавливает его между настройкой фикстуры и телом теста,
    и подмена не доживает до проверки.
    """
    out = stream if stream is not None else sys.stderr
    if not out.isatty():
        return
    if done % 50 and done != total:
        return
    out.write(f"\r  scanning… {done}/{total} · {100 * done // total}%")
    if done == total:
        out.write("\r" + " " * 40 + "\r")
    out.flush()


def cmd_scan(args):
    r = scan(args.root, project=args.project, on_progress=_progress)
    where = args.root or " · ".join(f"{AGENT_LABEL[a]} {n}" for a, n, _, _ in r["by_agent"])
    print()
    print(f"  buzzcut — {where or 'no agent logs found'}")
    print(f"  {r['files']} files · {_human_bytes(r['bytes'])}"
          + (f"  ·  filter: {args.project}" if args.project else ""))
    if not args.project:
        print("  (every project, not just this one — "
              "narrow with: buzzcut scan --project NAME)")
    print()
    if not r["occurrences"]:
        print("  No secrets found.\n")
        return 0

    print(f"  FOUND    {r['unique']} unique · {r['occurrences']} occurrences · "
          f"{r['files_hit']} files")
    print()
    if len(r["by_agent"]) > 1:
        print("  BY AGENT")
        for agent, _, occ, uniq in r["by_agent"]:
            print(f"    {AGENT_LABEL[agent]:<18}{uniq:>4} uniq. {occ:>6} occ.")
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
    for _, path, proj in log_files(root):
        if project and project not in proj:
            continue
        try:
            for line in read_lines(path):
                if len(line) < MIN_LINE or not maybe_secret(line):
                    continue
                for f in find_secrets(line):
                    d = hashlib.sha256(f.value.encode()).hexdigest()[:16]
                    out.setdefault(d, (f.kind, f.value, proj))
        except OSError:
            continue
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
    labels = shorten_projects({p for _, _, p in found.values()}, width=30)
    for kind, value, proj in found.values():
        verdict = check_key(kind, value)
        row = (KIND_LABEL.get(kind, kind), mask(value), labels[proj])
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


def _codex_busy(paths):
    """PID процессов, которые держат эти файлы открытыми (обычно сам Codex).
    Без lsof — любые процессы codex. Если и этого не узнать, считаем занятым:
    лучше не почистить, чем писать в базу под работающим Codex."""
    try:
        out = subprocess.run(["lsof", "-t", "--", *paths], capture_output=True, text=True).stdout
        return sorted({int(p) for p in out.split()})
    except (OSError, ValueError):
        pass
    try:
        out = subprocess.run(["ps", "-A", "-o", "pid=,comm="], capture_output=True, text=True).stdout
    except OSError:
        return [0]
    rows = (line.strip().partition(" ") for line in out.splitlines())
    return sorted(int(pid) for pid, _, comm in rows
                  if os.path.basename(comm.strip()).lower().startswith("codex"))


def cmd_clean(args):
    entries = log_files(args.root)
    wanted = lambda proj: not args.project or args.project in proj  # noqa: E731
    claude = [p for a, p, proj in entries if a == "claude" and wanted(proj)]
    codex_logs = [p for a, p, proj in entries if a == "codex" and not p.endswith(".sqlite") and wanted(proj)]
    codex_dbs = [p for a, p, _ in entries if a == "codex" and p.endswith(".sqlite")]
    ids = None
    if args.project:  # в базах Codex режем только строки сессий этого проекта
        ids = [i for i in map(codex_session_id, codex_logs) if i]
        codex_dbs = codex_dbs if ids else []

    # Бэкап повторяет путь от домашнего каталога: .claude/projects/…, .codex/…
    backup = args.backup or os.path.join(HOME, ".buzzcut-backup")
    base = args.root or HOME
    total, touched = 0, 0

    def tally(n):
        nonlocal total, touched
        if n:
            total += n
            touched += 1

    for path in claude:
        tally(clean_file(path, backup_dir=backup, dry_run=args.dry_run, root=base))

    codex = codex_logs + codex_dbs
    busy = _codex_busy(codex) if codex and not args.dry_run else []
    if busy:
        print(f"\n  Codex is running (pid {', '.join(map(str, busy))}), so its logs were left as they are.")
        print("  Quit Codex completely and run clean again.")
    else:
        for path in codex_logs:
            tally(clean_file(path, backup_dir=backup, dry_run=args.dry_run, root=base, keep_length=True))
        for path in codex_dbs:
            tally(clean_sqlite(path, backup_dir=backup, dry_run=args.dry_run, root=base, thread_ids=ids))

    verb = "would cut" if args.dry_run else "cut"
    print(f"\n  {verb} {total} occurrences in {touched} files")
    if args.dry_run:
        print("  Dry run. Drop --dry-run to apply.\n")
    elif total:
        print(f"  Backup: {backup}")
        print("  It still holds the keys. Delete it once you've checked everything works.\n")
    else:
        print()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="buzzcut", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", help="read only this folder (laid out like ~/.claude/projects)")
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
