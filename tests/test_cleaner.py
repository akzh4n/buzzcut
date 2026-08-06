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
