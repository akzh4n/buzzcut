"""Детектор секретов в тексте.

Цена ошибок несимметрична: ложное срабатывание режет данные у работающего
агента, пропуск лишь сохраняет статус-кво. Поэтому структурные паттерны
(ENV-присваивания) проходят через фильтр правдоподобия, а провайдерские
токены — нет: у них форма достаточно специфична сама по себе.
"""

import math
import re
from collections import namedtuple

Finding = namedtuple("Finding", "kind start end value")

REDACTION = "***REDACTED by buzzcut: {kind}***"

# Токены с фиксированным префиксом провайдера. Форма самодостаточна.
PROVIDER_PATTERNS = [
    ("anthropic",   re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}")),
    # \b обязателен: без него `risk-assessment-framework-2026` — это «sk-…».
    ("openai",      re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("github",      re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("aws",         re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("google",      re.compile(r"\bAIza[A-Za-z0-9_-]{30,}")),
    ("slack",       re.compile(r"\bxox[bpaso]-[A-Za-z0-9-]{16,}")),
    ("telegram",    re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{30,}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# Структурные формы — секрет узнаётся по обрамлению, а не по себе.
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
URL_CREDS = re.compile(r"://[^\s:/@]+:([^\s:/@]{6,})@")
ENV_ASSIGN = re.compile(r"\b([A-Z][A-Z0-9_]{2,})\s*=\s*(?:\\?[\"'])?([A-Za-z0-9_\-./+]{16,})")

# В JSONL перевод строки хранится как два символа `\` и `n`, а не как перевод
# строки. Дамп `cat .env` лежит одной строкой: `A=1\nB=2\nC=3`. Для регулярок
# это делает `1\nB` одним словом — граница пропадает, и всё после первой
# переменной теряется (на 4 308 файлах так пропадало 38 ключей).
#
# Замена строго той же длины (2 символа → 2 пробела): смещения находок обязаны
# оставаться валидными для ИСХОДНОЙ строки, иначе `clean` вырежет не тот кусок.
ESCAPED_WHITESPACE = re.compile(r"\\[nrt]")


def _normalize(text):
    return ESCAPED_WHITESPACE.sub("  ", text)

# Ворота по имени переменной. Без них `WT2=/path/DEV-604` и `HEAD=<sha>`
# неотличимы от `CORE_INTERNAL_SECRET=<hex>`: значения устроены одинаково.
# Проверено на 4306 файлах — без этого 60% находок были путями и git-ссылками.
SECRET_NAME = re.compile(
    r"SECRET|TOKEN|PASSWORD|PASSWD|_PWD|API_?KEY|ACCESS_?KEY|PRIVATE|"
    r"CREDENTIAL|AUTH|SIGNING|CLIENT_ID|CLIENT_KEY|SALT|DSN|_KEY\b|^KEY$"
)

# Публичные по построению: сборщики фронтенда вшивают такие переменные в бандл,
# значение и так уезжает в браузер. Без этих ворот `NEXT_PUBLIC_..._API_KEY`
# проходил по слову `API_KEY` внутри, и хук резал бы его у агента, который
# правит фронтовый конфиг. Провайдерских токенов ворота не касаются: там
# форма самодостаточна, и попадание такого ключа в бандл — уже инцидент.
PUBLIC_PREFIX = re.compile(r"^(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC)_")

MIN_SECRET_LEN = 16
MIN_ENTROPY = 3.0

# Значения-заглушки: встречаются в документации и шаблонах .env.
PLACEHOLDER_WORDS = (
    "your", "changeme", "change_me", "example", "placeholder", "redacted",
    "dummy", "sample", "insert", "replace", "todo", "fixme", "xxxx",
    "here", "secret_key", "notset", "none", "null", "test",
)


def _entropy(value):
    if not value:
        return 0.0
    total = len(value)
    return -sum(
        (n / total) * math.log2(n / total)
        for n in {c: value.count(c) for c in set(value)}.values()
    )


def _looks_like_secret(value):
    """Фильтр правдоподобия для структурных находок.

    Настоящий секрет почти всегда смешивает регистры/цифры и не читается
    как слово. Заглушки из шаблонов — наоборот.
    """
    if len(value) < MIN_SECRET_LEN:
        return False
    low = value.lower()
    if any(w in low for w in PLACEHOLDER_WORDS):
        return False
    if not (any(c.isdigit() for c in value) and any(c.isalpha() for c in value)):
        return False
    return _entropy(value) >= MIN_ENTROPY


def find_secrets(text):
    """Находки, отсортированные по позиции. Пересечения разрешаются в пользу
    более специфичного (провайдерского) совпадения."""
    if not text:
        return []

    # Ищем по нормализованной копии, значения режем из оригинала: длина
    # совпадает посимвольно, поэтому смещения годятся для обоих.
    probe = _normalize(text)

    found = []
    taken = []

    def claim(start, end):
        if any(start < e and s < end for s, e in taken):
            return False
        taken.append((start, end))
        return True

    for kind, rx in PROVIDER_PATTERNS:
        for m in rx.finditer(probe):
            if claim(m.start(), m.end()):
                found.append(Finding(kind, m.start(), m.end(), text[m.start():m.end()]))

    for kind, rx in (("jwt", JWT), ("url_credentials", URL_CREDS), ("env_secret", ENV_ASSIGN)):
        for m in rx.finditer(probe):
            # у JWT значимо всё совпадение, у остальных — только группа значения
            if kind == "jwt":
                start, end = m.span()
            elif kind == "env_secret":
                name = m.group(1)
                if PUBLIC_PREFIX.match(name) or not SECRET_NAME.search(name):
                    continue
                start, end = m.span(2)
            else:
                start, end = m.span(1)
            value = text[start:end]
            if kind == "env_secret" and not _looks_like_secret(value):
                continue
            if claim(start, end):
                found.append(Finding(kind, start, end, value))

    return sorted(found, key=lambda f: f.start)


def redact(text, keep_length=False):
    """Текст с вырезанными значениями. Если резать нечего — тот же объект.

    keep_length: вместо метки звёздочки той же длины в байтах. Нужна там, где
    кто-то помнит байтовые смещения в файле (Codex): размер не меняется.
    """
    found = find_secrets(text)
    if not found:
        return text
    out = []
    prev = 0
    for f in found:
        out.append(text[prev:f.start])
        out.append("*" * len(f.value.encode("utf-8", "surrogateescape")) if keep_length
                   else REDACTION.format(kind=f.kind))
        prev = f.end
    out.append(text[prev:])
    return "".join(out)
