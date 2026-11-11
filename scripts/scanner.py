"""Обход транскриптов Claude Code и агрегация находок.

Значения секретов наружу не отдаются: для подсчёта уникальных используется
усечённый sha256, для показа — маска. Так отчёт можно вставить в тикет или
статью, не устроив вторую утечку.
"""

import glob
import hashlib
import json
import os
import pathlib
import re
import sqlite3
from collections import Counter, defaultdict

from detect import find_secrets

HOME = os.path.expanduser("~")
DEFAULT_ROOT = os.path.join(HOME, ".claude", "projects")

# Codex пишет тот же JSONL, что и Claude Code, но держит вторую копию сессий
# в своей SQLite и помнит байтовые смещения в логах. Поэтому `clean` режет
# у него маской той же длины, и в логах, и в базах.
CODEX_DIRS = (".codex/sessions", ".codex/archived_sessions")
CODEX_FILES = (".codex/history.jsonl",)  # история промптов
CODEX_DBS = (".codex/thread_history_*.sqlite", ".codex/logs_*.sqlite")
AGENT_LABEL = {"claude": "Claude Code", "codex": "Codex"}

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


def _codex_meta(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.loads(fh.readline())["payload"]
    except (OSError, ValueError, KeyError, TypeError):
        return {}


def _codex_project(path):
    """Проект сессии Codex — её cwd, записанный так же, как Claude Code
    называет папки проектов: тогда один проект двух агентов — одна строка."""
    cwd = _codex_meta(path).get("cwd")
    return re.sub(r"[^A-Za-z0-9]", "-", cwd) if isinstance(cwd, str) and cwd else "codex"


def codex_session_id(path):
    """id сессии Codex: он же thread_id её строк в базах Codex."""
    return _codex_meta(path).get("id")


def log_files(root=None, home=None):
    """[(агент, путь, проект)] для каждого лога, который buzzcut умеет читать.

    `root` — один каталог в формате ~/.claude/projects (тесты, демо): тогда
    читается только он.
    """
    if root:
        return [("claude", p, project_of(p, root)) for p in transcript_paths(root)]
    home = home or HOME
    claude = os.path.join(home, ".claude", "projects")
    out = [("claude", p, project_of(p, claude)) for p in transcript_paths(claude)]
    for d in CODEX_DIRS:
        for p in sorted(glob.glob(os.path.join(home, d, "**", "*.jsonl"), recursive=True)):
            out.append(("codex", p, _codex_project(p)))
    for pattern in CODEX_FILES:
        out += [("codex", p, "codex prompts") for p in sorted(glob.glob(os.path.join(home, pattern)))]
    for pattern in CODEX_DBS:
        out += [("codex", p, "codex database") for p in sorted(glob.glob(os.path.join(home, pattern)))]
    return out


def open_sqlite_ro(path):
    """(соединение только на чтение, таблицы) или (None, []). База в режиме WAL
    без файла -shm не открывается даже на чтение, тогда читаем как неизменяемую."""
    for query in ("?mode=ro", "?mode=ro&immutable=1"):
        try:
            con = sqlite3.connect(pathlib.Path(path).as_uri() + query, uri=True)
            tables = [t for (t,) in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            return con, tables
        except sqlite3.Error:
            continue
    return None, []


def _sqlite_texts(path):
    """Текстовые значения всех таблиц, только чтение."""
    con, tables = open_sqlite_ro(path)
    if con is None:
        return
    try:
        for t in tables:
            cols = con.execute(f'PRAGMA table_info("{t}")').fetchall()
            for c in cols:
                if not any(k in (c[2] or "").upper() for k in ("CHAR", "CLOB", "TEXT")):
                    continue
                for (v,) in con.execute(f'SELECT "{c[1]}" FROM "{t}"'):
                    if isinstance(v, str):
                        yield v
    except sqlite3.Error:
        return
    finally:
        con.close()


def read_lines(path):
    """Текст лога порциями: JSONL построчно, база — по значениям."""
    if path.endswith(".sqlite"):
        yield from _sqlite_texts(path)
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from fh


# Префиксы формата публичны: `sk-proj-` говорит, чей это ключ, но не сам ключ.
PUBLIC_FORMAT = re.compile(
    r"^(?:sk-ant-[a-z]+\d*-|sk-proj-|sk-|gh[pousr]_|github_pat_|AKIA|ASIA|AIza|xox[bpaso]-)")


def mask(value):
    """Подпись, по которой человек узнаёт ключ, не получая его.

    Из самого секрета видны максимум 4 последних символа, и только у длинных:
    прежние «6 спереди + 3 сзади» у 20-символьного пароля раскрывали почти
    половину, а вывод `check` предлагается вставлять в тикет.
    """
    m = PUBLIC_FORMAT.match(value)
    prefix = m.group(0) if m else ""
    rest = value[len(prefix):]
    return prefix + "…" + (rest[-4:] if len(rest) >= 20 else "")


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
    # Префикс снимаем только с имён-путей (`-Users-...`). Подпись вроде
    # `codex` (сессия без заголовка) путём не является и не должна обнулять
    # общий префикс остальных.
    is_path = [len(s) > 1 and s[0] == "" for s in split]
    paths = [s for s, ok in zip(split, is_path) if ok]
    # Общий префикс не имеет права съесть имя целиком: у самого короткого
    # проекта должен остаться хотя бы один сегмент. Из одного имени префикс
    # выводить не из чего — «всё, кроме последнего сегмента» подписало бы
    # `...-melo-app` как `app`. Лучше длинно и точно.
    common = 0
    if len(paths) > 1:
        limit = min(len(s) for s in paths) - 1
        while common < limit and len({s[common] for s in paths}) == 1:
            common += 1

    return {n: _elide("-".join(s[common:]) if ok else n, width)
            for n, s, ok in zip(names, split, is_path)}


def scan(root=None, project=None, on_progress=None, home=None):
    """Сводка по логам всех агентов.

    По умолчанию обходит всё, а не текущий проект: логи лежат глобально, и
    ключ, утёкший в соседнем проекте, живой ровно так же. `project` — подстрока
    имени, сужает выборку (воркtree подхватываются вместе с основным проектом,
    у них общий префикс). `root` — один каталог в формате ~/.claude/projects.
    `on_progress(done, total)` зовётся после каждого файла.
    """
    by_kind = Counter()
    by_project = Counter()
    by_agent = Counter()
    digests = defaultdict(set)
    project_digests = defaultdict(set)
    agent_digests = defaultdict(set)
    agent_files = Counter()
    files_hit = set()
    per_file = Counter()
    examples = {}
    n_files = 0
    n_bytes = 0

    entries = log_files(root, home)
    if project:
        entries = [e for e in entries if project in e[2]]
    total = len(entries)

    for done, (agent, path, proj) in enumerate(entries, 1):
        n_files += 1
        agent_files[agent] += 1
        if on_progress:
            on_progress(done, total)
        try:
            n_bytes += os.path.getsize(path)
            for line in read_lines(path):
                if len(line) < MIN_LINE or not maybe_secret(line):
                    continue
                for f in find_secrets(line):
                    d = hashlib.sha256(f.value.encode()).hexdigest()[:16]
                    by_kind[f.kind] += 1
                    by_project[proj] += 1
                    by_agent[agent] += 1
                    digests[f.kind].add(d)
                    project_digests[proj].add(d)
                    agent_digests[agent].add(d)
                    files_hit.add(path)
                    per_file[path] += 1
                    examples.setdefault(d, (f.kind, mask(f.value), proj))
        except OSError:
            continue

    return {
        "files": n_files,
        "bytes": n_bytes,
        "files_hit": len(files_hit),
        "occurrences": sum(by_kind.values()),
        "unique": sum(len(v) for v in digests.values()),
        "by_kind": [(k, by_kind[k], len(digests[k])) for k, _ in by_kind.most_common()],
        "by_project": [(p, by_project[p], len(project_digests[p])) for p, _ in by_project.most_common()],
        "by_agent": [(a, agent_files[a], by_agent[a], len(agent_digests[a])) for a in AGENT_LABEL if agent_files[a]],
        "worst_files": per_file.most_common(10),
        "unique_index": examples,
    }
