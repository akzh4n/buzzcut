"""Правило «пережило / частично / потеряно» и чтение JSONL.

Это правило и даёт число гейта, поэтому граничные случаи зафиксированы явно.
"""

import json

from recall import classify, load_events


class TestClassify:
    def test_verbatim_quote_is_kept(self):
        msg = "првоерь логи почему то посты threads не выходят"
        assert classify(msg, f'- "{msg}"') == "kept"

    def test_absent_message_is_lost(self):
        assert classify("не трогай миграции они катятся отдельно", "3. Files: a.ts") == "lost"

    def test_paraphrase_above_threshold_is_kept(self):
        msg = "не трогай миграции они катятся отдельно"
        summary = "просил не трогать миграции — катятся отдельно, отдельным пайплайном"
        assert classify(msg, summary) == "kept"

    def test_weak_word_overlap_is_lost_not_kept(self):
        msg = "перепиши обработчик подписок целиком"
        summary = "правились лимиты подписок в другом месте"
        assert classify(msg, summary) == "lost"

    def test_threshold_is_adjustable(self):
        msg = "перепиши обработчик подписок целиком"
        summary = "правились лимиты подписок в другом месте"
        assert classify(msg, summary, threshold=0.2) == "kept"


class TestLoadEvents:
    def test_reads_one_event_per_line(self, tmp_path):
        p = tmp_path / "s.jsonl"
        p.write_text(
            json.dumps({"type": "user", "uuid": "u1"}) + "\n"
            + json.dumps({"type": "assistant", "uuid": "a1"}) + "\n",
            encoding="utf-8",
        )
        assert [e["uuid"] for e in load_events(str(p))] == ["u1", "a1"]

    def test_skips_malformed_line_instead_of_crashing(self, tmp_path):
        p = tmp_path / "s.jsonl"
        p.write_text(
            json.dumps({"type": "user", "uuid": "u1"}) + "\n"
            + "{ это не json\n"
            + json.dumps({"type": "user", "uuid": "u2"}) + "\n",
            encoding="utf-8",
        )
        assert [e["uuid"] for e in load_events(str(p))] == ["u1", "u2"]
