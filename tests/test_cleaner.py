"""Вырезание секретов из транскриптов на диске.

Единственный модуль, который пишет в пользовательские файлы, — поэтому
инварианты жёсткие: без бэкапа не пишем, JSONL остаётся построчно валидным,
повторный прогон ничего не меняет.
"""

import json

import pytest

from cleaner import clean_file, clean_text


# Собирается в рантайме — см. tests/test_detect.py::_fake
FAKE_KEY = "sk-" + "proj-" + "QZ7tRvKeq7xK2mZp9vLbT4dRfA8sYcXe"

SECRET_LINE = json.dumps({
    "type": "user",
    "message": {"role": "user", "content": f"OPENAI_API_KEY={FAKE_KEY}"},
}, ensure_ascii=False)

CLEAN_LINE = json.dumps({
    "type": "user",
    "message": {"role": "user", "content": "npm run build"},
}, ensure_ascii=False)


class TestCleanText:
    def test_removes_the_secret(self):
        out, n = clean_text(SECRET_LINE)
        assert n == 1
        assert FAKE_KEY not in out

    def test_result_is_still_valid_json(self):
        out, _ = clean_text(SECRET_LINE)
        assert json.loads(out)["message"]["content"].startswith("OPENAI_API_KEY=")

    def test_line_without_secrets_is_untouched(self):
        out, n = clean_text(CLEAN_LINE)
        assert n == 0
        assert out == CLEAN_LINE

    def test_second_pass_changes_nothing(self):
        once, _ = clean_text(SECRET_LINE)
        twice, n = clean_text(once)
        assert n == 0
        assert twice == once


class TestCleanFile:
    def _write(self, tmp_path, lines):
        p = tmp_path / "session.jsonl"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return p

    def test_reports_how_many_were_cut(self, tmp_path):
        p = self._write(tmp_path, [CLEAN_LINE, SECRET_LINE, SECRET_LINE])
        assert clean_file(str(p), backup_dir=str(tmp_path / "bak")) == 2

    def test_dry_run_leaves_the_file_alone(self, tmp_path):
        p = self._write(tmp_path, [SECRET_LINE])
        before = p.read_text(encoding="utf-8")
        assert clean_file(str(p), backup_dir=str(tmp_path / "bak"), dry_run=True) == 1
        assert p.read_text(encoding="utf-8") == before

    def test_writes_a_backup_before_changing_anything(self, tmp_path):
        p = self._write(tmp_path, [SECRET_LINE])
        bak = tmp_path / "bak"
        clean_file(str(p), backup_dir=str(bak))
        saved = list(bak.rglob("*.jsonl"))
        assert len(saved) == 1
        assert "sk-proj-QZ7tRvKe" in saved[0].read_text(encoding="utf-8")

    def test_no_backup_when_there_is_nothing_to_cut(self, tmp_path):
        p = self._write(tmp_path, [CLEAN_LINE])
        bak = tmp_path / "bak"
        assert clean_file(str(p), backup_dir=str(bak)) == 0
        assert not bak.exists()

    def test_every_line_stays_parseable(self, tmp_path):
        p = self._write(tmp_path, [CLEAN_LINE, SECRET_LINE])
        clean_file(str(p), backup_dir=str(tmp_path / "bak"))
        for line in p.read_text(encoding="utf-8").splitlines():
            json.loads(line)

    def test_line_count_is_preserved(self, tmp_path):
        p = self._write(tmp_path, [CLEAN_LINE, SECRET_LINE, CLEAN_LINE])
        clean_file(str(p), backup_dir=str(tmp_path / "bak"))
        assert len(p.read_text(encoding="utf-8").splitlines()) == 3

    def test_rerun_is_a_noop(self, tmp_path):
        p = self._write(tmp_path, [SECRET_LINE])
        bak = str(tmp_path / "bak")
        clean_file(str(p), backup_dir=bak)
        after = p.read_text(encoding="utf-8")
        assert clean_file(str(p), backup_dir=bak) == 0
        assert p.read_text(encoding="utf-8") == after

    def test_refuses_to_run_without_a_backup_dir(self, tmp_path):
        p = self._write(tmp_path, [SECRET_LINE])
        with pytest.raises(ValueError):
            clean_file(str(p), backup_dir=None)


class TestBackupLayout:
    """Subagent transcripts all sit in a folder called `subagents`, and the same
    agent-*.jsonl name does occur in two sessions on a real machine. 0.1.1 kept
    only `parent/name`, so the second backup overwrote the first — the one copy
    of the original was gone."""

    def test_same_name_in_two_sessions_keeps_both_backups(self, tmp_path):
        root = tmp_path / "projects"
        a = root / "proj" / "session-a" / "subagents" / "agent-1.jsonl"
        b = root / "proj" / "session-b" / "subagents" / "agent-1.jsonl"
        for p, tag in ((a, "A"), (b, "B")):
            p.parent.mkdir(parents=True)
            p.write_text(SECRET_LINE + "\n" + json.dumps({"tag": tag}) + "\n", encoding="utf-8")

        bak = tmp_path / "bak"
        for p in (a, b):
            clean_file(str(p), backup_dir=str(bak), root=str(root))

        saved = sorted(bak.rglob("*.jsonl"))
        assert len(saved) == 2
        assert {'"tag": "A"' in s.read_text() for s in saved} == {True, False}

    def test_backup_mirrors_the_path_under_root(self, tmp_path):
        root = tmp_path / "projects"
        p = root / "proj" / "session.jsonl"
        p.parent.mkdir(parents=True)
        p.write_text(SECRET_LINE + "\n", encoding="utf-8")
        clean_file(str(p), backup_dir=str(tmp_path / "bak"), root=str(root))
        assert (tmp_path / "bak" / "proj" / "session.jsonl").is_file()
