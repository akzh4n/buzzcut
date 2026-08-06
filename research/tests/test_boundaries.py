"""Разбор границ компакции и определение того, что не пережило границу.

Поля compactMetadata сверены с реальным событием из сессии 87d0d0e5:
trigger / preTokens / postTokens / preservedMessages.uuids.
"""

from recall import dropped_instructions, find_boundaries


def human(uuid, text):
    return {
        "type": "user",
        "uuid": uuid,
        "message": {"role": "user", "content": text},
    }


def boundary(uuid, preserved, trigger="auto", pre=1000470, post=21994):
    return {
        "type": "system",
        "subtype": "compact_boundary",
        "uuid": uuid,
        "compactMetadata": {
            "trigger": trigger,
            "preTokens": pre,
            "postTokens": post,
            "preservedMessages": {"uuids": list(preserved)},
        },
    }


def summary(text):
    return {
        "type": "user",
        "uuid": "sum-1",
        "isCompactSummary": True,
        "message": {"role": "user", "content": text},
    }


class TestFindBoundaries:
    def test_session_without_compaction_has_no_boundaries(self):
        assert find_boundaries([human("u1", "почини обработчик подписок")]) == []

    def test_reads_trigger_and_token_counts(self):
        events = [boundary("b1", []), summary("6. All user messages: …")]
        found = find_boundaries(events)[0]
        assert found["trigger"] == "auto"
        assert found["pre_tokens"] == 1000470
        assert found["post_tokens"] == 21994

    def test_attaches_summary_that_follows_the_boundary(self):
        events = [boundary("b1", []), summary("текст саммари")]
        assert find_boundaries(events)[0]["summary"] == "текст саммари"

    def test_preserved_uuids_are_collected(self):
        events = [boundary("b1", ["u2", "u3"]), summary("s")]
        assert find_boundaries(events)[0]["preserved_uuids"] == {"u2", "u3"}

    def test_boundary_without_summary_is_skipped(self):
        assert find_boundaries([boundary("b1", [])]) == []


class TestDroppedInstructions:
    def test_instruction_before_boundary_is_dropped(self):
        events = [
            human("u1", "не трогай миграции они катятся отдельно"),
            boundary("b1", []),
            summary("s"),
        ]
        dropped = dropped_instructions(events, find_boundaries(events)[0])
        assert [d["text"] for d in dropped] == ["не трогай миграции они катятся отдельно"]

    def test_preserved_message_is_not_dropped(self):
        events = [
            human("u1", "не трогай миграции они катятся отдельно"),
            boundary("b1", ["u1"]),
            summary("s"),
        ]
        assert dropped_instructions(events, find_boundaries(events)[0]) == []

    def test_short_acknowledgement_is_not_counted(self):
        events = [human("u1", "дальше"), boundary("b1", []), summary("s")]
        assert dropped_instructions(events, find_boundaries(events)[0]) == []

    def test_message_after_boundary_is_not_counted(self):
        events = [
            boundary("b1", []),
            summary("s"),
            human("u9", "не трогай миграции они катятся отдельно"),
        ]
        assert dropped_instructions(events, find_boundaries(events)[0]) == []

    def test_second_boundary_counts_only_messages_since_the_first(self):
        events = [
            human("u1", "первое указание про биллинг и подписки целиком"),
            boundary("b1", []),
            summary("s1"),
            human("u2", "второе указание про вебхуки и ретраи целиком"),
            boundary("b2", []),
            summary("s2"),
        ]
        second = find_boundaries(events)[1]
        assert [d["text"] for d in dropped_instructions(events, second)] == [
            "второе указание про вебхуки и ретраи целиком"
        ]
