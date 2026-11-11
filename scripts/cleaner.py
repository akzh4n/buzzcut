"""Вырезание секретов из транскриптов.

Единственная часть buzzcut, которая пишет в файлы пользователя. Правила:
бэкап делается до записи и только когда есть что резать; запись атомарна
через временный файл; повторный прогон — no-op.
"""

import os
import shutil
import tempfile

from detect import find_secrets, redact


def clean_text(text):
    """(текст без секретов, сколько вырезано)."""
    found = find_secrets(text)
    if not found:
        return text, 0
    return redact(text), len(found)


def _backup(path, backup_dir, root):
    # Путь целиком, а не «папка/файл»: у сабагентов папка всегда `subagents`,
    # и одноимённые agent-*.jsonl из разных сессий затирали бы копии друг друга.
    dest = os.path.join(backup_dir, os.path.relpath(path, root))
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.copy2(path, dest)


def clean_file(path, backup_dir, dry_run=False, root="/"):
    """Вырезает секреты из одного JSONL. Возвращает число вырезанных.

    Файл переписывается только если что-то нашлось, и только после бэкапа.
    Бэкап повторяет путь файла относительно `root`.
    """
    if not backup_dir and not dry_run:
        raise ValueError("clean_file needs backup_dir: no backup, no write")

    lines, total = [], 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.rstrip("\n")
            cleaned, n = clean_text(stripped)
            total += n
            lines.append(cleaned)

    if total == 0 or dry_run:
        return total

    _backup(path, backup_dir, root)

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".buzzcut")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            for line in lines:
                out.write(line + "\n")
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise

    return total
