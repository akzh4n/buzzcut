"""Вырезание секретов из логов агентов.

Единственная часть buzzcut, которая пишет в файлы пользователя. Правила:
бэкап делается до записи и только когда есть что резать; запись атомарна
через временный файл; повторный прогон — no-op. Байты, которые не трогаем,
остаются байт в байт: битый UTF-8 и переводы строк не нормализуются.
"""

import os
import shutil
import sqlite3
import tempfile

from detect import find_secrets, redact
from scanner import MIN_LINE, maybe_secret, open_sqlite_ro

ENC = dict(encoding="utf-8", errors="surrogateescape", newline="")


def clean_text(text, keep_length=False):
    """(текст без секретов, сколько вырезано)."""
    found = find_secrets(text)
    if not found:
        return text, 0
    return redact(text, keep_length), len(found)


def _backup(path, backup_dir, root):
    # Путь целиком, а не «папка/файл»: у сабагентов папка всегда `subagents`,
    # и одноимённые agent-*.jsonl из разных сессий затирали бы копии друг друга.
    dest = os.path.join(backup_dir, os.path.relpath(path, root))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(path, dest)


def clean_file(path, backup_dir, dry_run=False, root="/", keep_length=False):
    """Вырезает секреты из одного JSONL. Возвращает число вырезанных.

    Файл переписывается только если что-то нашлось, и только после бэкапа.
    Бэкап повторяет путь файла относительно `root`. `keep_length` — маска
    той же длины в байтах вместо метки: размер файла не меняется.
    """
    if not backup_dir and not dry_run:
        raise ValueError("clean_file needs backup_dir: no backup, no write")

    lines, total = [], 0
    with open(path, **ENC) as fh:
        for line in fh:
            cleaned, n = clean_text(line, keep_length)
            total += n
            lines.append(cleaned)

    if total == 0 or dry_run:
        return total

    _backup(path, backup_dir, root)

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".buzzcut")
    try:
        with os.fdopen(fd, "w", **ENC) as out:
            out.write("".join(lines))
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    return total


def _text_columns(con, table):
    cols = con.execute(f'PRAGMA table_info("{table}")').fetchall()
    return [c[1] for c in cols if any(t in (c[2] or "").upper() for t in ("CHAR", "CLOB", "TEXT"))]


def clean_sqlite(path, backup_dir, dry_run=False, root="/", thread_ids=None):
    """Вырезает секреты из текстовых колонок базы Codex. Возвращает число вырезанных.

    Маска той же длины, как и в его логах. `thread_ids` — только строки этих
    сессий; таблицы без колонки thread_id тогда не трогаются. Ищем через
    соединение только на чтение; пишет второе, после бэкапа. Вызывающий
    обязан убедиться, что базу никто не держит открытой.
    """
    if not backup_dir and not dry_run:
        raise ValueError("clean_sqlite needs backup_dir: no backup, no write")

    ro, tables = open_sqlite_ro(path)
    if ro is None:
        return 0
    updates, total = [], 0
    try:
        for t in tables:
            names = [c[1] for c in ro.execute(f'PRAGMA table_info("{t}")')]
            if thread_ids is not None and "thread_id" not in names:
                continue
            for c in _text_columns(ro, t):
                q, args = f'SELECT rowid, "{c}" FROM "{t}"', ()
                if thread_ids is not None:
                    q += f" WHERE thread_id IN ({','.join('?' * len(thread_ids))})"
                    args = tuple(thread_ids)
                try:
                    rows = ro.execute(q, args).fetchall()
                except sqlite3.OperationalError:
                    continue  # WITHOUT ROWID: адресовать строку нечем, не трогаем
                for rowid, v in rows:
                    if not isinstance(v, str) or len(v) < MIN_LINE or not maybe_secret(v):
                        continue
                    cleaned, n = clean_text(v, keep_length=True)
                    if n:
                        updates.append((t, c, rowid, cleaned))
                        total += n
    finally:
        ro.close()

    if total == 0 or dry_run:
        return total

    con = sqlite3.connect(path)
    try:
        dest = os.path.join(backup_dir, os.path.relpath(path, root))
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        bak = sqlite3.connect(dest)
        try:
            con.backup(bak)  # согласованная копия вместе с содержимым WAL
        finally:
            bak.close()

        # secure_delete обнуляет старые версии записей, checkpoint переносит
        # всё из WAL в базу и обрезает WAL: старых значений не остаётся нигде.
        con.execute("PRAGMA secure_delete=ON")
        with con:
            for t, c, rowid, cleaned in updates:
                con.execute(f'UPDATE "{t}" SET "{c}"=? WHERE rowid=?', (cleaned, rowid))
        con.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        con.close()
    return total
