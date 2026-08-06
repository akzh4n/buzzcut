"""Обход транскриптов Claude Code и агрегация находок.

Значения секретов наружу не отдаются: для подсчёта уникальных используется
усечённый sha256, для показа — маска. Так отчёт можно вставить в тикет или
статью, не устроив вторую утечку.
"""

import glob
import hashlib
import os
import re
from collections import Counter, defaultdict

from detect import find_secrets

DEFAULT_ROOT = os.path.expanduser("~/.claude/projects")

# Предварительный отсев: одна альтернатива вместо одиннадцати проходов по
# строке. Обязан быть строго ШИРЕ детектора — строка, которую он отбросил,
# уже никогда не будет проверена, и оптимизация превратится в тихий пропуск.
# Инвариант закреплён в tests/test_scanner.py::TestPrefilter.
PREFILTER = re.compile(
    r"[A-Z][A-Z0-9_]{2,}\s*=|sk-|gh[pousr]_|github_pat_|AKIA|ASIA|AIza|"
    r"xox[bpaso]-|eyJ|://|PRIVATE KEY|:AA"
)

# Короче этого не бывает даже самый компактный секрет вместе с обрамлением.
MIN_LINE = 40


def maybe_secret(line):
    return PREFILTER.search(line) is not None


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


def _elide(name, width):
    """Сжатие с середины. Хвост длиннее головы намеренно: различает проекты
    именно он (`...worktrees-insights` против `...worktrees-templates`),
    а голова у всех и так почти одинаковая."""
    if len(name) <= width:
        return name
    head = max(0, (width - 1) // 3)
    tail = width - 1 - head
    return name[:head] + "…" + name[-tail:]


def shorten_projects(names, width=46):
    """{полное имя: подпись для отчёта}.

    Имя проекта — это путь с заменёнными слэшами, поэтому у всех записей
    общий и бесполезный префикс вроде `-Users-<имя>-Desktop-Development-`.
    Обрезка справа делала воркtree одного проекта неразличимыми: они
    расходятся только в хвосте. Сначала снимаем общий префикс по границам
    сегментов, и лишь остаток при нужде сжимаем с середины.
    """
    names = list(names)
    if not names:
        return {}

    split = [n.split("-") for n in names]
    # Общий префикс не имеет права съесть имя целиком: у самого короткого
    # проекта должен остаться хотя бы один сегмент. Из одного имени префикс
    # выводить не из чего — «всё, кроме последнего сегмента» подписало бы
    # `...-melo-app` как `app`. Лучше длинно и точно.
    common = 0
    if len(split) > 1:
        limit = min(len(s) for s in split) - 1
        while common < limit and len({s[common] for s in split}) == 1:
            common += 1

    return {n: _elide("-".join(s[common:]), width) for n, s in zip(names, split)}


def scan(root=DEFAULT_ROOT, project=None, on_progress=None):
    """Сводка по транскриптам.

    По умолчанию обходит весь `root`, а не текущий проект: транскрипты лежат
    глобально, и ключ, утёкший в соседнем проекте, живой ровно так же.
    `project` — подстрока имени, сужает выборку (воркtree подхватываются
    вместе с основным проектом, у них общий префикс).
    `on_progress(done, total)` зовётся после каждого файла.
    """
    by_kind = Counter()
    by_project = Counter()
    digests = defaultdict(set)
    project_digests = defaultdict(set)
    files_hit = set()
    per_file = Counter()
    examples = {}
    n_files = 0
    n_bytes = 0

    paths = transcript_paths(root)
    if project:
        paths = [p for p in paths if project in project_of(p, root)]
    total = len(paths)

    for done, path in enumerate(paths, 1):
        n_files += 1
        if on_progress:
            on_progress(done, total)
        try:
            n_bytes += os.path.getsize(path)
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
