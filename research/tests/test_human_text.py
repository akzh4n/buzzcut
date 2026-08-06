"""Извлечение человеческого текста из событий транскрипта.

Формы взяты из реальных сессий ~/.claude/projects (90 файлов, 06.08.2026):
шум составляет большую часть user-событий и обязан отсекаться до счёта recall.
"""

from recall import human_text


def user_event(content, **extra):
    ev = {"type": "user", "message": {"role": "user", "content": content}}
    ev.update(extra)
    return ev


def test_plain_string_message_is_human():
    assert human_text(user_event("добавь ретрай в обработчик")) == "добавь ретрай в обработчик"


def test_text_block_message_is_human():
    ev = user_event([{"type": "text", "text": "надо доработать логику"}])
    assert human_text(ev) == "надо доработать логику"


def test_text_alongside_image_keeps_only_text():
    ev = user_event(
        [
            {"type": "image", "source": {"type": "base64", "data": "..."}},
            {"type": "text", "text": "првоерь логи почему то посты не выходят"},
        ]
    )
    assert human_text(ev) == "првоерь логи почему то посты не выходят"


def test_tool_result_is_not_human():
    ev = user_event([{"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}])
    assert human_text(ev) is None


def test_meta_event_is_not_human():
    ev = user_event([{"type": "text", "text": "[Image: original 3024x1964]"}], isMeta=True)
    assert human_text(ev) is None


def test_compact_summary_is_not_human():
    ev = user_event("This session is being continued…", isCompactSummary=True)
    assert human_text(ev) is None


def test_assistant_event_is_not_human():
    ev = {"type": "assistant", "message": {"role": "assistant", "content": "готово"}}
    assert human_text(ev) is None


def test_task_notification_is_not_human():
    ev = user_event("<task-notification>\n<task-id>w8pzmayxd</task-id>\n</task-notification>")
    assert human_text(ev) is None


def test_slash_command_invocation_is_not_human():
    ev = user_event(
        "<command-message>model</command-message>\n<command-name>/model</command-name>"
    )
    assert human_text(ev) is None


def test_local_command_stdout_is_not_human():
    ev = user_event("<local-command-stdout>Set model to claude-fable-5</local-command-stdout>")
    assert human_text(ev) is None


def test_interrupt_marker_is_not_human():
    assert human_text(user_event("[Request interrupted by user]")) is None


def test_ide_context_block_is_stripped_but_message_survives():
    ev = user_event(
        "<ide_opened_file>The user opened the file /tmp/a.ts in the IDE</ide_opened_file>\n"
        "перепиши этот хендлер"
    )
    assert human_text(ev) == "перепиши этот хендлер"


def test_event_that_is_only_ide_context_is_not_human():
    ev = user_event("<ide_selection>The user selected lines 74 to 74</ide_selection>")
    assert human_text(ev) is None


def test_system_reminder_is_stripped_but_message_survives():
    ev = user_event(
        "<system-reminder>Codebase instructions below</system-reminder>\nпочини биллинг"
    )
    assert human_text(ev) == "почини биллинг"


def test_sidechain_event_is_not_human():
    ev = user_event("проанализируй файл", isSidechain=True)
    assert human_text(ev) is None
