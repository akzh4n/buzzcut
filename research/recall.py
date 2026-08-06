"""buzzcut — измерение recall пользовательских сообщений в саммари компакции."""

import argparse
import glob
import json
import os
import re
import statistics

# Блоки, которые Claude Code вставляет в user-события от своего имени.
# Всё это не написано человеком и не должно попадать в счёт recall.
NOISE_TAGS = (
    "task-notification",
    "command-message",
    "command-name",
    "command-args",
    "local-command-stdout",
    "system-reminder",
    "user-prompt-submit-hook",
    "ide_opened_file",
    "ide_selection",
    "bash-input",
    "bash-stdout",
    "bash-stderr",
)

_NOISE_RE = re.compile(
    r"<(" + "|".join(NOISE_TAGS) + r")>.*?</\1>|<(" + "|".join(NOISE_TAGS) + r")>.*",
    re.DOTALL,
)
_INTERRUPT_RE = re.compile(r"\[Request interrupted by user[^\]]*\]")


def _strip_noise(text):
    text = _NOISE_RE.sub("", text)
    text = _INTERRUPT_RE.sub("", text)
    return text.strip()


STOPWORDS = {
    # русский
    "это", "эта", "этот", "эти", "что", "как", "для", "или", "они", "она", "оно",
    "все", "всё", "так", "там", "тут", "был", "была", "было", "были", "быть",
    "есть", "его", "ему", "нее", "неё", "них", "ним", "вот", "где", "кто", "чем",
    "чём", "при", "над", "под", "про", "без", "уже", "еще", "ещё", "мне", "тебе",
    "меня", "тебя", "себя", "если", "чтобы", "когда", "потом", "тоже", "также",
    "нужно", "может", "можно", "типа", "типо",
    # английский
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "was", "one",
    "our", "out", "has", "him", "his", "how", "its", "may", "now", "see", "two",
    "way", "who", "did", "get", "use", "this", "that", "with", "from", "have",
    "been", "will", "your", "they", "them", "then", "than", "when", "what",
    "which", "there", "their", "would", "could", "should", "into", "some",
}

MIN_TOKEN_LEN = 3
MIN_INSTRUCTION_TOKENS = 4
MAX_INSTRUCTION_CHARS = 600
QUOTE_NGRAM = 3

_WORD_RE = re.compile(r"[^\W_]+(?:_[^\W_]+)*", re.UNICODE)


def _words(text):
    """Все слова в порядке следования, нормализованные. Стоп-слова сохраняются."""
    return _WORD_RE.findall(text.lower())


def content_tokens(text):
    """Значимые токены: без стоп-слов и коротких хвостов вроде `.ts`."""
    return {
        w for w in _words(text) if len(w) >= MIN_TOKEN_LEN and w not in STOPWORDS
    }


# Признаки строки, которую человек вставил, а не напечатал.
SHELL_COMMANDS = (
    "swapon|docker|kubectl|helm|grep|ssh|scp|rsync|curl|wget|cd|ls|cat|tail|head|less"
    "|npm|pnpm|yarn|node|python3?|pip3?|git|sudo|systemctl|journalctl|service|free|ps"
    "|kill|pkill|awk|sed|export|source|echo|mkdir|rm|cp|mv|chmod|chown|nginx|psql"
    "|redis-cli|uvicorn|brew|apt|apt-get|df|du|top|htop|uptime|whoami|which|env"
    "|printenv|openssl|jq|tar|unzip|make|bash|sh|zsh"
)

_PASTE_LINE = re.compile(
    r"""
      ^\s*\S+@[\w.\-]+                      # root@host, flowlyai@MacBook
    | ^\s*(?:%s)\b                          # голая команда в начале строки
    | ^\s*[|$#>]                            # продолжение пайпа, приглашение
    | \\\s*$                                # перенос строки шелла
    | ^\s*={3,}                             # ===== баннер =====
    | ^Traceback\ \(                        # питоновский трейсбек
    | ^\s*File\ ".*",\ line\ \d+            # его же кадры
    | ^\s*\w+Error\b                        # ProgrammingError: …
    | ^\s*[A-Za-z_][A-Za-z0-9_]*=           # MCP_ZAPIS_CLIENT_ID=…
    | [0-9a-f]{16,}                         # hex-идентификатор сессии
    | \t | \ {3,}                           # колонки табличного вывода
    """
    % SHELL_COMMANDS,
    re.VERBOSE,
)

# Скобки и кавычки JSON: три и больше на строку — это фрагмент запроса, не речь.
_JSONISH = re.compile(r"[{}\"\[\]]")
MAX_JSONISH_CHARS = 3


def _is_paste_line(line):
    return bool(_PASTE_LINE.search(line)) or len(_JSONISH.findall(line)) >= MAX_JSONISH_CHARS


def instruction_text(text):
    """Только то, что человек напечатал: вставленный вывод команд убран."""
    kept = [line for line in text.splitlines() if line.strip() and not _is_paste_line(line)]
    return "\n".join(kept).strip()


def is_instruction(text):
    """Несёт ли сообщение указание.

    «дальше» — нет: слишком коротко. Дамп docker — нет: это не печатали.
    Вставленный документ на несколько экранов — нет: это не указание, а материал.
    """
    prose = instruction_text(text)
    if len(prose) > MAX_INSTRUCTION_CHARS:
        return False
    return len(content_tokens(prose)) >= MIN_INSTRUCTION_TOKENS


def quoted_in(message, summary, n=QUOTE_NGRAM):
    """Встречается ли в саммари дословная n-грамма из сообщения."""
    mw, sw = _words(message), _words(summary)
    if len(mw) < n or len(sw) < n:
        return False
    grams = {tuple(sw[i:i + n]) for i in range(len(sw) - n + 1)}
    return any(tuple(mw[i:i + n]) in grams for i in range(len(mw) - n + 1))


def token_recall(message, summary):
    """Доля значимых токенов сообщения, встретившихся в саммари."""
    tokens = content_tokens(message)
    if not tokens:
        return 0.0
    return len(tokens & content_tokens(summary)) / len(tokens)


KEEP_THRESHOLD = 0.6


def classify(message, summary, threshold=KEEP_THRESHOLD):
    """«kept», если саммари цитирует сообщение или удержало его словарь."""
    if quoted_in(message, summary):
        return "kept"
    return "kept" if token_recall(message, summary) >= threshold else "lost"


def load_events(path):
    """События сессии. Битые строки пропускаются, а не роняют разбор."""
    events = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except ValueError:
                continue
    return events


def _message_text(event):
    """Сырой текст сообщения без фильтрации: str-контент или text-блоки."""
    content = (event.get("message") or {}).get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        blocks = [b for b in content if isinstance(b, dict)]
        if any(b.get("type") == "tool_result" for b in blocks):
            return None
        return "\n".join(b.get("text", "") for b in blocks if b.get("type") == "text")
    return None


def human_text(event):
    """Человеческий текст события или None, если событие писал не человек."""
    if event.get("type") != "user":
        return None
    if event.get("isMeta") or event.get("isCompactSummary") or event.get("isSidechain"):
        return None

    text = _message_text(event)
    if text is None:
        return None

    return _strip_noise(text) or None


def find_boundaries(events):
    """Границы компакции с привязанным к каждой текстом саммари.

    Граница без последующего саммари пропускается: измерять нечего.
    """
    boundaries = []
    start = 0
    for i, ev in enumerate(events):
        if ev.get("subtype") != "compact_boundary":
            continue
        summary = None
        for nxt in events[i + 1:]:
            if nxt.get("isCompactSummary"):
                summary = _message_text(nxt)
                break
            if nxt.get("subtype") == "compact_boundary":
                break
        if not summary:
            continue
        meta = ev.get("compactMetadata") or {}
        preserved = (meta.get("preservedMessages") or {}).get("uuids") or []
        boundaries.append(
            {
                "index": i,
                "start": start,
                "uuid": ev.get("uuid"),
                "trigger": meta.get("trigger"),
                "pre_tokens": meta.get("preTokens"),
                "post_tokens": meta.get("postTokens"),
                "preserved_uuids": set(preserved),
                "summary": summary,
            }
        )
        start = i
    return boundaries


def dropped_instructions(events, boundary):
    """Содержательные сообщения человека, не пережившие эту границу.

    Считаются только сообщения, появившиеся после предыдущей границы: всё,
    что было раньше, уже представлено предыдущим саммари.
    """
    dropped = []
    for ev in events[boundary["start"]:boundary["index"]]:
        text = human_text(ev)
        if not text or not is_instruction(text):
            continue
        if ev.get("uuid") in boundary["preserved_uuids"]:
            continue
        dropped.append({"uuid": ev.get("uuid"), "text": instruction_text(text)})
    return dropped


# ─────────────────────────── прогон и отчёт ───────────────────────────

DEFAULT_ROOT = os.path.expanduser("~/.claude/projects")


def session_paths(root):
    """Только главные треды. Сабагенты лежат глубже и сессиями не являются."""
    return sorted(glob.glob(os.path.join(root, "*", "*.jsonl")))


def measure(root=DEFAULT_ROOT, threshold=KEEP_THRESHOLD):
    """По каждой границе компакции — сколько указаний не пережило саммари."""
    results = []
    for path in session_paths(root):
        events = load_events(path)
        boundaries = find_boundaries(events)
        if not boundaries:
            continue
        for n, b in enumerate(boundaries, 1):
            dropped = dropped_instructions(events, b)
            lost = [
                d for d in dropped if classify(d["text"], b["summary"], threshold) == "lost"
            ]
            results.append(
                {
                    "session": os.path.basename(path)[:8],
                    "project": os.path.basename(os.path.dirname(path)),
                    "n": n,
                    "trigger": b["trigger"],
                    "pre_tokens": b["pre_tokens"] or 0,
                    "summary_chars": len(b["summary"]),
                    "dropped": len(dropped),
                    "lost": len(lost),
                    "lost_texts": [d["text"] for d in lost],
                }
            )
    return results


def _pct(part, whole):
    return 100.0 * part / whole if whole else 0.0


def report(results, threshold):
    out = []
    add = out.append
    measurable = [r for r in results if r["dropped"] > 0]
    with_loss = [r for r in measurable if r["lost"] > 0]
    total_dropped = sum(r["dropped"] for r in measurable)
    total_lost = sum(r["lost"] for r in measurable)

    add("")
    add("  buzzcut — recall указаний в саммари компакции")
    add(f"  порог совпадения словаря: {threshold}")
    add("")
    add(f"  компакций найдено                {len(results)}")
    add(f"  из них измеримых                 {len(measurable)}   (были выброшены указания)")
    add(f"  сессий с компакцией              {len({r['session'] for r in results})}")
    add("")
    add("  ГЛАВНОЕ ЧИСЛО")
    add(
        f"  компакций, потерявших ≥1 указание   {len(with_loss)} из {len(measurable)}"
        f"   ({_pct(len(with_loss), len(measurable)):.0f}%)"
    )
    add("")
    add(
        f"  указаний выброшено границей      {total_dropped}"
    )
    add(
        f"  из них не пережили саммари       {total_lost}"
        f"   ({_pct(total_lost, total_dropped):.0f}%)"
    )
    add("")

    add("  ПО РАЗМЕРУ КОНТЕКСТА ПЕРЕД КОМПАКЦИЕЙ")
    buckets = [(0, 200_000), (200_000, 500_000), (500_000, 900_000), (900_000, 10**9)]
    for lo, hi in buckets:
        grp = [r for r in measurable if lo <= r["pre_tokens"] < hi]
        if not grp:
            continue
        d = sum(r["dropped"] for r in grp)
        l = sum(r["lost"] for r in grp)
        label = f"{lo // 1000}k–{hi // 1000}k" if hi < 10**9 else f"{lo // 1000}k+"
        add(
            f"    {label:<12} компакций {len(grp):>3}   указаний {d:>4}   "
            f"потеряно {l:>4}  ({_pct(l, d):.0f}%)"
        )
    add("")

    add("  ПО ТРИГГЕРУ")
    for trig in ("auto", "manual"):
        grp = [r for r in measurable if r["trigger"] == trig]
        if not grp:
            continue
        d = sum(r["dropped"] for r in grp)
        l = sum(r["lost"] for r in grp)
        add(
            f"    {trig:<8} компакций {len(grp):>3}   указаний {d:>4}   "
            f"потеряно {l:>4}  ({_pct(l, d):.0f}%)"
        )
    add("")

    worst = sorted(measurable, key=lambda r: (-r["lost"], -r["dropped"]))[:8]
    add("  ХУДШИЕ КОМПАКЦИИ")
    for r in worst:
        if not r["lost"]:
            continue
        add(
            f"    {r['session']}  #{r['n']}  {r['trigger']:<6} "
            f"{r['pre_tokens'] // 1000:>5}k   потеряно {r['lost']:>3} из {r['dropped']:>3}"
        )
    add("")

    add("  ПРИМЕРЫ ПОТЕРЯННЫХ УКАЗАНИЙ")
    shown = 0
    for r in worst:
        for t in r["lost_texts"][:2]:
            add(f"    [{r['session']}] {t[:110]}")
            shown += 1
            if shown >= 10:
                break
        if shown >= 10:
            break
    add("")
    return "\n".join(out)


def sensitivity(root, thresholds):
    lines = ["  ЧУВСТВИТЕЛЬНОСТЬ К ПОРОГУ", ""]
    lines.append("    порог   компакций с потерей   потеряно указаний")
    for t in thresholds:
        res = measure(root, t)
        measurable = [r for r in res if r["dropped"] > 0]
        with_loss = [r for r in measurable if r["lost"] > 0]
        d = sum(r["dropped"] for r in measurable)
        l = sum(r["lost"] for r in measurable)
        lines.append(
            f"    {t:<7} {len(with_loss):>3}/{len(measurable):<3} "
            f"({_pct(len(with_loss), len(measurable)):>3.0f}%)"
            f"        {l:>4}/{d:<4} ({_pct(l, d):>3.0f}%)"
        )
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="recall указаний в саммари компакции")
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--threshold", type=float, default=KEEP_THRESHOLD)
    ap.add_argument("--sensitivity", action="store_true")
    ap.add_argument("--json", dest="json_out")
    args = ap.parse_args()

    results = measure(args.root, args.threshold)
    print(report(results, args.threshold))
    if args.sensitivity:
        print(sensitivity(args.root, [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(results, fh, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    main()
