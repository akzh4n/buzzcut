#!/usr/bin/env python3
"""buzzcut — находит и вырезает секреты, осевшие в транскриптах Claude Code.

  buzzcut scan            что лежит в ~/.claude/projects (read-only)
  buzzcut check --yes     какие из найденных ключей ещё живые (ходит в сеть)
  buzzcut clean           вырезать, с бэкапом
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

KIND_RU = {
    "openai": "OpenAI", "anthropic": "Anthropic", "github": "GitHub PAT",
    "aws": "AWS", "google": "Google API", "slack": "Slack",
    "telegram": "Telegram", "private_key": "приватный ключ",
    "jwt": "JWT", "url_credentials": "креды в URL", "env_secret": "ENV-секрет",
}


def _human_bytes(n):
    return f"{n / 1e9:.2f} ГБ" if n >= 1e9 else f"{n / 1e6:.0f} МБ"


def _progress(done, total):
    """Полоса в stderr. Под Claude Code вывод команды не стримится — там её
    просто не видно, и это нормально: она для запуска из терминала, где
    двухминутная тишина выглядит как зависание."""
    if not sys.stderr.isatty():
        return
    if done % 50 and done != total:
        return
    sys.stderr.write(f"\r  сканирую… {done}/{total} · {100 * done // total}%")
    if done == total:
        sys.stderr.write("\r" + " " * 40 + "\r")
    sys.stderr.flush()


def cmd_scan(args):
    r = scan(args.root, project=args.project, on_progress=_progress)
    scope = f"{args.root}  ·  фильтр: {args.project}" if args.project else args.root
    print()
    print(f"  buzzcut — {scope}")
    print(f"  {r['files']} файлов · {_human_bytes(r['bytes'])}")
    if not args.project:
        print("  (все проекты Claude Code, не только текущий — "
              "сузить: buzzcut scan --project ИМЯ)")
    print()
    if not r["occurrences"]:
        print("  Секретов не найдено.\n")
        return 0

    print(f"  НАЙДЕНО    {r['unique']} уникальных · {r['occurrences']} вхождений · "
          f"{r['files_hit']} файлов")
    print()
    print("  ПО ПРОЕКТАМ")
    top = r["by_project"][:10]
    labels = shorten_projects([p for p, _, _ in top], width=46)
    for proj, occ, uniq in top:
        print(f"    {labels[proj]:<46}{uniq:>4} ключей {occ:>6} вхожд.")
    print()
    print("  ПО ТИПАМ")
    for kind, occ, uniq in r["by_kind"]:
        print(f"    {KIND_RU.get(kind, kind):<18}{uniq:>4} уник. {occ:>6} вхожд.")
    print()
    print("  buzzcut check --yes    проверить, какие ещё живые")
    print("  buzzcut clean          вырезать из файлов")
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
        print("\n  Секретов не найдено.\n")
        return 0

    auto = [(k, v, p) for k, v, p in found.values() if check_key(k, "") != MANUAL]
    print(f"\n  Найдено {len(found)} уникальных ключей.")
    print(f"  Автоматически проверяемых: {len(auto)} — остальные требуют решения человека.")
    print()
    if not args.yes:
        print("  Проверка отправит каждый ключ его собственному провайдеру")
        print("  (read-only эндпоинт). Ключи не уходят никуда больше.")
        print("  Запусти с --yes, если согласен.\n")
        return 1

    live, dead, manual = [], [], []
    for kind, value, proj in found.values():
        verdict = check_key(kind, value)
        row = (KIND_RU.get(kind, kind), mask(value), proj)
        (live if verdict == LIVE else dead if verdict == DEAD else manual).append(row)

    if live:
        print("  ЖИВЫЕ — ротировать сейчас")
        for k, m, p in live:
            print(f"    {k:<16}{m:<18}{p}")
        print()
    if dead:
        print(f"  МЁРТВЫЕ — {len(dead)}, можно просто вычистить\n")
    if manual:
        print(f"  РЕШАЕТ ЧЕЛОВЕК — {len(manual)}")
        for k, m, p in manual[:8]:
            print(f"    {k:<16}{m:<18}{p}")
        if len(manual) > 8:
            print(f"    …ещё {len(manual) - 8}")
        print()
    print(f"  ИТОГО   {len(live)} живых · {len(dead)} мёртвых · {len(manual)} на решение\n")
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

    verb = "будет вырезано" if args.dry_run else "вырезано"
    print(f"\n  {verb} {total} вхождений в {touched} файлах")
    if args.dry_run:
        print("  Это сухой прогон. Убери --dry-run, чтобы применить.\n")
    elif total:
        print(f"  Бэкап: {backup}\n")
    else:
        print()
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="buzzcut", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=DEFAULT_ROOT)
    sub = ap.add_subparsers(dest="cmd")

    PROJECT_HELP = "ограничить проектами, чьё имя содержит эту подстроку"

    s = sub.add_parser("scan", help="отчёт, ничего не меняет")
    s.add_argument("--project", help=PROJECT_HELP)
    s.set_defaults(fn=cmd_scan)

    c = sub.add_parser("check", help="какие ключи ещё живые (сеть)")
    c.add_argument("--yes", action="store_true", help="подтвердить сетевые запросы")
    c.add_argument("--project", help=PROJECT_HELP)
    c.set_defaults(fn=cmd_check)

    cl = sub.add_parser("clean", help="вырезать секреты из транскриптов")
    cl.add_argument("--dry-run", action="store_true")
    cl.add_argument("--project", help=PROJECT_HELP)
    cl.add_argument("--backup", help="куда класть бэкап")
    cl.set_defaults(fn=cmd_clean)

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
