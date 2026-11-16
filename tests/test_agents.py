"""Logs of every agent buzzcut reads: Claude Code and Codex.

Codex writes the same JSONL as Claude Code, but keeps a second copy of each
session in its own SQLite databases and remembers byte offsets into the logs.
So Codex is cleaned with masks of the same byte length, in the logs and in the
databases, and only while no process holds its files.
"""

import json
import os
import shutil
import sqlite3

import pytest

import buzzcut
import scanner
from scanner import log_files, scan, shorten_projects

FAKE_KEY = "sk-" + "proj-" + "QZ7tRvKeq7xK2mZp9vLbT4dRfA8sYcXe"
LEAK = json.dumps({"stdout": f"OPENAI_API_KEY={FAKE_KEY}"})
CODEX_LOG = ".codex/sessions/2026/11/04/rollout-1.jsonl"
SID, OTHER = "0000-alpha-session", "1111-other-session"


def rows(db, sql):
    con = sqlite3.connect(db)
    try:
        return [r[0] for r in con.execute(sql)]
    finally:
        con.close()


@pytest.fixture
def home(tmp_path, monkeypatch):
    claude = tmp_path / ".claude" / "projects" / "-Users-me-alpha" / "s.jsonl"
    claude.parent.mkdir(parents=True)
    claude.write_text(LEAK + "\n", encoding="utf-8")

    codex = tmp_path / CODEX_LOG
    codex.parent.mkdir(parents=True)
    meta = {"type": "session_meta", "payload": {"id": SID, "cwd": "/Users/me/alpha"}}
    codex.write_text(json.dumps(meta) + "\n" + LEAK + "\n", encoding="utf-8")

    con = sqlite3.connect(tmp_path / ".codex" / "thread_history_1.sqlite")
    con.execute("CREATE TABLE thread_items (thread_id TEXT, item_id TEXT, item_json TEXT)")
    con.executemany("INSERT INTO thread_items VALUES (?, ?, ?)", [(SID, "a", LEAK), (OTHER, "b", LEAK)])
    con.execute("CREATE TABLE notes (body TEXT)")  # no thread_id: belongs to no session
    con.execute("INSERT INTO notes VALUES (?)", (LEAK,))
    con.commit()
    con.close()

    con = sqlite3.connect(tmp_path / ".codex" / "logs_2.sqlite")
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("CREATE TABLE logs (id INTEGER PRIMARY KEY, thread_id TEXT, feedback_log_body TEXT)")
    con.execute("INSERT INTO logs (thread_id, feedback_log_body) VALUES (?, ?)", (SID, LEAK))
    con.commit()
    con.close()

    monkeypatch.setattr(scanner, "HOME", str(tmp_path))
    monkeypatch.setattr(buzzcut, "HOME", str(tmp_path))
    monkeypatch.setattr(buzzcut, "_codex_busy", lambda paths: [])
    return tmp_path


class TestFindsEveryAgent:
    def test_lists_logs_of_both(self, home):
        assert {a for a, _, _ in log_files()} == {"claude", "codex"}

    def test_scan_reads_the_codex_database_copies(self, home):
        # 1 Claude log + 1 Codex log + 3 rows in thread_history + 1 in logs
        assert scan()["occurrences"] == 6

    def test_a_codex_session_is_labelled_like_the_claude_project(self, home):
        labels = {p: proj for _, p, proj in log_files()}
        assert labels[str(home / CODEX_LOG)] == "-Users-me-alpha"

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

    def test_codex_logs_keep_their_exact_size(self, home):
        before = (home / CODEX_LOG).stat().st_size
        buzzcut.main(["clean"])
        after = (home / CODEX_LOG).read_text(encoding="utf-8")
        assert (home / CODEX_LOG).stat().st_size == before
        assert FAKE_KEY not in after
        for line in after.splitlines():
            json.loads(line)

    def test_codex_database_copies_are_cleaned(self, home):
        buzzcut.main(["clean"])
        db = home / ".codex"
        assert not any(FAKE_KEY in v for v in rows(db / "thread_history_1.sqlite", "SELECT item_json FROM thread_items"))
        assert not any(FAKE_KEY in v for v in rows(db / "logs_2.sqlite", "SELECT feedback_log_body FROM logs"))
        assert not (db / "logs_2.sqlite-wal").exists() or (db / "logs_2.sqlite-wal").stat().st_size == 0

    def test_project_limits_codex_databases_to_its_sessions(self, home):
        buzzcut.main(["clean", "--project", "alpha"])
        db = home / ".codex" / "thread_history_1.sqlite"
        items = dict(zip(rows(db, "SELECT thread_id FROM thread_items"), rows(db, "SELECT item_json FROM thread_items")))
        assert FAKE_KEY not in items[SID]
        assert FAKE_KEY in items[OTHER]
        assert FAKE_KEY in rows(db, "SELECT body FROM notes")[0]

    def test_leaves_codex_alone_while_it_is_running(self, home, monkeypatch, capsys):
        monkeypatch.setattr(buzzcut, "_codex_busy", lambda paths: [4242])
        log_before = (home / CODEX_LOG).read_bytes()
        db = home / ".codex" / "thread_history_1.sqlite"
        db_before = db.read_bytes()
        buzzcut.main(["clean"])
        assert (home / CODEX_LOG).read_bytes() == log_before
        assert db.read_bytes() == db_before
        assert "Codex is running (pid 4242)" in capsys.readouterr().out

    def test_dry_run_counts_codex_and_writes_nothing(self, home, capsys):
        log_before = (home / CODEX_LOG).read_bytes()
        buzzcut.main(["clean", "--dry-run"])
        assert "would cut 6 occurrences in 4 files" in capsys.readouterr().out
        assert (home / CODEX_LOG).read_bytes() == log_before

    def test_backups_mirror_the_path_from_home(self, home):
        buzzcut.main(["clean"])
        bak = home / ".buzzcut-backup"
        assert (bak / ".claude" / "projects" / "-Users-me-alpha" / "s.jsonl").is_file()
        assert FAKE_KEY in (bak / CODEX_LOG).read_text(encoding="utf-8")
        assert any(FAKE_KEY in v for v in rows(bak / ".codex" / "thread_history_1.sqlite",
                                                "SELECT item_json FROM thread_items"))

    def test_says_the_backup_still_holds_the_keys(self, home, capsys):
        buzzcut.main(["clean"])
        assert "It still holds the keys" in capsys.readouterr().out


class TestClaudeCopies:
    """Claude Code keeps a copy of every file the agent edited (to undo edits)
    and every prompt you typed. A key in .env ends up in both."""

    @pytest.fixture
    def copies(self, home):
        copy = home / ".claude" / "file-history" / "s" / "1f2e3d@v2"  # session s = the alpha transcript
        copy.parent.mkdir(parents=True)
        copy.write_text(f"NODE_ENV=production\nOPENAI_API_KEY={FAKE_KEY}\n", encoding="utf-8")
        orphan = home / ".claude" / "file-history" / "gone" / "9a8b7c@v1"
        orphan.parent.mkdir(parents=True)
        orphan.write_text(f"OPENAI_API_KEY={FAKE_KEY}\n", encoding="utf-8")
        prompts = home / ".claude" / "history.jsonl"
        prompts.write_text(json.dumps({"display": f"use {FAKE_KEY}"}) + "\n", encoding="utf-8")
        return copy, orphan, prompts

    def test_listed_under_their_project(self, home, copies):
        labels = {p: proj for _, p, proj in log_files()}
        copy, orphan, prompts = map(str, copies)
        assert labels[copy] == "-Users-me-alpha"
        assert labels[orphan] == "claude file backups"
        assert labels[prompts] == "claude prompts"

    def test_clean_cuts_them_and_warns_about_undo(self, home, copies, capsys):
        buzzcut.main(["clean"])
        for f in copies:
            assert FAKE_KEY not in f.read_text(encoding="utf-8")
        assert copies[0].read_text(encoding="utf-8").startswith("NODE_ENV=production\n")
        assert "2 of them are copies Claude Code keeps to undo edits" in capsys.readouterr().out

    def test_project_reaches_the_copies_of_that_project(self, home, copies):
        buzzcut.main(["clean", "--project", "alpha"])
        copy, orphan, _ = copies
        assert FAKE_KEY not in copy.read_text(encoding="utf-8")
        assert FAKE_KEY in orphan.read_text(encoding="utf-8")


@pytest.mark.skipif(not shutil.which("lsof"), reason="needs lsof")
class TestBusyCheck:
    def test_sees_a_process_holding_the_file(self, tmp_path):
        f = tmp_path / "held.sqlite"
        f.write_text("x")
        with open(f):
            assert os.getpid() in buzzcut._codex_busy([str(f)])

    def test_nobody_holds_a_closed_file(self, tmp_path):
        f = tmp_path / "free.sqlite"
        f.write_text("x")
        assert buzzcut._codex_busy([str(f)]) == []


class TestWalWithoutShm:
    def test_a_wal_database_without_its_shm_file_is_still_read(self, tmp_path):
        db = tmp_path / "t.sqlite"
        con = sqlite3.connect(db)
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES (?)", (LEAK,))
        con.commit()
        con.close()
        for extra in ("-wal", "-shm"):
            if os.path.exists(str(db) + extra):
                os.remove(str(db) + extra)
        assert any(FAKE_KEY in v for v in scanner.read_lines(str(db)))


class TestLabels:
    def test_a_non_path_label_does_not_block_prefix_stripping(self):
        labels = shorten_projects(["-Users-me-dev-alpha", "-Users-me-dev-beta", "codex"])
        assert labels == {"-Users-me-dev-alpha": "alpha", "-Users-me-dev-beta": "beta", "codex": "codex"}
