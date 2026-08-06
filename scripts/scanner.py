"""Обход транскриптов Claude Code и агрегация находок.

Значения секретов наружу не отдаются: для подсчёта уникальных используется
усечённый sha256, для показа — маска. Так отчёт можно вставить в тикет или
статью, не устроив вторую утечку.
"""

import glob
import hashlib
import os
from collections import Counter, defaultdict

from detect import find_secrets

DEFAULT_ROOT = os.path.expanduser("~/.claude/projects")


def transcript_paths(root=DEFAULT_ROOT):
    """Все транскрипты, включая сабагентов: секрет одинаково опасен в любом."""
    return sorted(glob.glob(os.path.join(root, "*", "**", "*.jsonl"), recursive=True))


def mask(value):
    if len(value) <= 10:
        return value[:2] + "…"
    return f"{value[:6]}…{value[-3:]}"


def project_of(path, root=DEFAULT_ROOT):
    rel = os.path.relpath(path, root)
    return rel.split(os.sep)[0]


def scan(root=DEFAULT_ROOT):
    """Сводка по всем транскриптам."""
    by_kind = Counter()
    by_project = Counter()
    digests = defaultdict(set)
    project_digests = defaultdict(set)
    files_hit = set()
    per_file = Counter()
    examples = {}
    n_files = 0
    n_bytes = 0

    for path in transcript_paths(root):
        n_files += 1
        try:
            n_bytes += os.path.getsize(path)
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError:
            continue
        proj = project_of(path, root)
        with fh:
            for line in fh:
                if len(line) < 40:
                    continue
                for f in find_secrets(line):
                    d = hashlib.sha256(f.value.encode()).hexdigest()[:16]
                    by_kind[f.kind] += 1
                    by_project[proj] += 1
                    digests[f.kind].add(d)
                    project_digests[proj].add(d)
                    files_hit.add(path)
                    per_file[path] += 1
                    examples.setdefault(d, (f.kind, mask(f.value), proj))

    return {
        "files": n_files,
        "bytes": n_bytes,
        "files_hit": len(files_hit),
        "occurrences": sum(by_kind.values()),
        "unique": sum(len(v) for v in digests.values()),
        "by_kind": [(k, by_kind[k], len(digests[k])) for k, _ in by_kind.most_common()],
        "by_project": [(p, by_project[p], len(project_digests[p])) for p, _ in by_project.most_common()],
        "worst_files": per_file.most_common(10),
        "unique_index": examples,
    }
