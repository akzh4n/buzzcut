"""PostToolUse-хук: режет секреты из вывода инструмента до того, как его
увидит модель.

Команда не подменяется и не блокируется — правится только результат. Это
отличает подход от подстановки `sed` в саму команду: агент получает ровно то,
что запрашивал, минус значения секретов, и не начинает чинить «сломанную»
команду.

Форма ответа сохраняется: Claude Code валидирует updatedToolOutput против
outputSchema инструмента, поэтому строки правятся на месте, а структура —
никогда.
"""

import json
import sys

from detect import find_secrets, redact

MAX_BYTES = 2_000_000  # выше этого не тратим время: вывод всё равно урезан


def redact_payload(node):
    """Копия структуры с вырезанными секретами и число вырезанных."""
    if isinstance(node, str):
        n = len(find_secrets(node))
        return (redact(node) if n else node), n
    if isinstance(node, dict):
        out, total = {}, 0
        for k, v in node.items():
            out[k], n = redact_payload(v)
            total += n
        return out, total
    if isinstance(node, list):
        out, total = [], 0
        for v in node:
            cleaned, n = redact_payload(v)
            out.append(cleaned)
            total += n
        return out, total
    return node, 0


def handle(event):
    """Ответ хука или None, если вмешиваться не нужно."""
    response = event.get("tool_response")
    if response is None:
        return None

    updated, n = redact_payload(response)
    if n == 0:
        return None

    plural = "secret" if n == 1 else "secrets"
    return {
        "systemMessage": f"✂ buzzcut: {n} {plural} cut from {event.get('tool_name', '?')} output",
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "updatedToolOutput": updated,
        },
    }


def main():
    try:
        raw = sys.stdin.read(MAX_BYTES)
        event = json.loads(raw)
    except Exception:
        return 0  # молча пропускаем: хук не имеет права ломать сессию

    try:
        result = handle(event)
    except Exception:
        return 0

    if result:
        json.dump(result, sys.stdout, ensure_ascii=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
