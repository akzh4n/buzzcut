"""Хук PostToolUse.

Claude Code валидирует updatedToolOutput против outputSchema инструмента
(«PostToolUse hook returned updatedToolOutput that does not match»), поэтому
редактирование обязано сохранять форму ответа — правим строки на месте,
структуру не пересобираем.
"""

import json

from guard import handle, redact_payload


def bash_event(stdout, stderr=""):
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "cat .env"},
        "tool_response": {"stdout": stdout, "stderr": stderr, "interrupted": False},
    }


# Собирается в рантайме — целого токена в исходнике быть не должно,
# иначе push protection блокирует репозиторий за его собственные фикстуры.
FAKE_KEY = "sk-" + "proj-" + "QZ7tRvKeq7xK2mZp9vLbT4dRfA8sYcXe"
SECRET = f"OPENAI_API_KEY={FAKE_KEY}"


class TestRedactPayload:
    def test_cuts_the_secret_from_stdout(self):
        out, n = redact_payload(bash_event(SECRET)["tool_response"])
        assert n == 1
        assert FAKE_KEY not in out["stdout"]

    def test_preserves_the_response_shape(self):
        src = bash_event(SECRET)["tool_response"]
        out, _ = redact_payload(src)
        assert set(out) == set(src)
        assert out["interrupted"] is False

    def test_also_cleans_stderr(self):
        out, n = redact_payload(bash_event("ok", SECRET)["tool_response"])
        assert n == 1
        assert FAKE_KEY not in out["stderr"]

    def test_walks_nested_structures(self):
        src = {"items": [{"text": SECRET}, {"text": "clean"}]}
        out, n = redact_payload(src)
        assert n == 1
        assert FAKE_KEY not in json.dumps(out)
        assert out["items"][1]["text"] == "clean"

    def test_non_string_leaves_are_untouched(self):
        src = {"code": 0, "ok": True, "ratio": 1.5, "nothing": None}
        out, n = redact_payload(src)
        assert n == 0
        assert out == src

    def test_clean_payload_reports_zero(self):
        out, n = redact_payload(bash_event("npm run build")["tool_response"])
        assert n == 0


class TestHandle:
    def test_stays_silent_when_there_is_nothing_to_cut(self):
        assert handle(bash_event("all good")) is None

    def test_returns_updated_output_under_the_right_event_name(self):
        res = handle(bash_event(SECRET))
        hso = res["hookSpecificOutput"]
        assert hso["hookEventName"] == "PostToolUse"
        assert FAKE_KEY not in json.dumps(hso["updatedToolOutput"])

    def test_tells_the_user_what_was_cut(self):
        res = handle(bash_event(SECRET))
        assert "buzzcut" in res["systemMessage"]
        assert "1" in res["systemMessage"]

    def test_ignores_events_without_a_response(self):
        assert handle({"tool_name": "Bash", "tool_input": {}}) is None

    def test_survives_a_string_response(self):
        res = handle({"tool_name": "Read", "tool_response": SECRET})
        assert FAKE_KEY not in json.dumps(res["hookSpecificOutput"]["updatedToolOutput"])
