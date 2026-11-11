"""Logs of every agent buzzcut reads: Claude Code and Codex.

Codex writes the same JSONL as Claude Code, so it is scanned the same way.
It is never cleaned: Codex keeps a second copy of each session in its own
SQLite database and remembers byte offsets into the logs, so rewriting a log
would leave the copy behind and could break Codex's history.
"""

import json

import pytest

import buzzcut
import scanner
from scanner import log_files, scan, shorten_projects

FAKE_KEY = "sk-" + "proj-" + "QZ7tRvKeq7xK2mZp9vLbT4dRfA8sYcXe"
LEAK = json.dumps({"stdout": f"OPENAI_API_KEY={FAKE_KEY}"})
CODEX_LOG = ".codex/sessions/2026/11/04/rollout-1.jsonl"


@pytest.fixture
def home(tmp_path, monkeypatch):
    claude = tmp_path / ".claude" / "projects" / "-Users-me-alpha" / "s.jsonl"
    claude.parent.mkdir(parents=True)
    claude.write_text(LEAK + "\n", encoding="utf-8")

    codex = tmp_path / CODEX_LOG
    codex.parent.mkdir(parents=True)
    meta = {"type": "session_meta", "payload": {"cwd": "/Users/me/alpha"}}
    codex.write_text(json.dumps(meta) + "\n" + LEAK + "\n", encoding="utf-8")

    monkeypatch.setattr(scanner, "HOME", str(tmp_path))
    monkeypatch.setattr(buzzcut, "HOME", str(tmp_path))
    return tmp_path


class TestFindsEveryAgent:
    def test_lists_logs_of_both(self, home):
        assert {a for a, _, _ in log_files()} == {"claude", "codex"}

    def test_a_codex_session_is_labelled_like_the_claude_project(self, home):
        labels = {a: p for a, _, p in log_files()}
        assert labels["codex"] == labels["claude"] == "-Users-me-alpha"

    def test_a_codex_session_without_a_header_is_still_scanned(self, home):
        bad = home / ".codex" / "sessions" / "2026" / "11" / "04" / "rollout-2.jsonl"
        bad.write_text("not json\n" + LEAK + "\n", encoding="utf-8")
        assert ("codex", str(bad), "codex") in log_files()

    def test_scan_reports_each_agent(self, home):
        r = scan()
        assert {a: uniq for a, _, _, uniq in r["by_agent"]} == {"claude": 1, "codex": 1}
        assert r["unique"] == 1  # the same key in two places is one key

    def test_root_reads_only_that_folder(self, home):
        r = scan(str(home / ".claude" / "projects"))
        assert [a for a, *_ in r["by_agent"]] == ["claude"]


class TestClean:
    def test_cleans_claude_code_logs(self, home):
        buzzcut.main(["clean"])
        claude = home / ".claude" / "projects" / "-Users-me-alpha" / "s.jsonl"
        assert FAKE_KEY not in claude.read_text(encoding="utf-8")

    def test_never_writes_to_codex_logs(self, home):
        before = (home / CODEX_LOG).read_bytes()
        buzzcut.main(["clean"])
        assert (home / CODEX_LOG).read_bytes() == before

    def test_says_why_codex_was_left_alone(self, home, capsys):
        buzzcut.main(["clean"])
        assert "Codex logs are left as they are" in capsys.readouterr().out

    def test_backups_mirror_the_path_from_home(self, home):
        buzzcut.main(["clean"])
        bak = home / ".buzzcut-backup"
        assert (bak / ".claude" / "projects" / "-Users-me-alpha" / "s.jsonl").is_file()
        assert not (bak / ".codex").exists()


class TestLabels:
    def test_a_non_path_label_does_not_block_prefix_stripping(self):
        labels = shorten_projects(["-Users-me-dev-alpha", "-Users-me-dev-beta", "codex"])
        assert labels == {"-Users-me-dev-alpha": "alpha", "-Users-me-dev-beta": "beta", "codex": "codex"}
