"""Обход транскриптов и подготовка отчёта.

Имена проектов в ~/.claude/projects — это пути с заменёнными слэшами, поэтому
они длинные и почти целиком состоят из общего префикса. Наивная обрезка по
ширине колонки делает разные воркtree визуально одинаковыми: у пользователя
в отчёте три строки `-Users-...-contentgen` с разными числами, и выглядит
это как сбой подсчёта, хотя проекты действительно разные.
"""

import json

import pytest

from scanner import project_of, scan, shorten_projects

FAKE_KEY = "sk-" + "proj-" + "QZ7tRvKeq7xK2mZp9vLbT4dRfA8sYcXe"

REAL = [
    "-Users-flowlyai-Desktop-Development-contentgen",
    "-Users-flowlyai-Desktop-Development-contentgen--claude-worktrees-insights",
    "-Users-flowlyai-Desktop-Development-contentgen-apps-web",
    "-Users-flowlyai-Desktop-Development-flowly",
    "-Users-flowlyai",
]


class TestShortenProjects:
    def test_every_label_is_distinct(self):
        labels = shorten_projects(REAL, width=46)
        assert len(set(labels.values())) == len(REAL)

    def test_nothing_exceeds_the_column(self):
        for label in shorten_projects(REAL, width=46).values():
            assert len(label) <= 46

    def test_common_prefix_is_dropped(self):
        labels = shorten_projects(REAL[:4], width=46)
        assert labels["-Users-flowlyai-Desktop-Development-flowly"] == "flowly"

    def test_the_distinguishing_tail_is_kept(self):
        labels = shorten_projects(REAL, width=46)
        assert labels[REAL[1]].endswith("insights")

    def test_no_label_is_empty(self):
        for label in shorten_projects(REAL, width=46).values():
            assert label.strip()

    def test_a_lone_project_is_not_stripped_at_all(self):
        """Общий префикс не из чего выводить, когда имя одно: срезание «всего,
        кроме последнего сегмента» подписывает `...-melo-app` как `app`.
        Лучше длинно и точно, чем коротко и неверно."""
        only = ["-Users-flowlyai-Desktop-Development-melo-app"]
        assert shorten_projects(only, width=46)[only[0]] == only[0]

    def test_two_names_are_enough_to_infer_the_prefix(self):
        names = [
            "-Users-flowlyai-Desktop-Development-melo-app",
            "-Users-flowlyai-Desktop-Development-flowly",
        ]
        assert set(shorten_projects(names, width=46).values()) == {"melo-app", "flowly"}

    def test_long_tail_is_elided_not_truncated(self):
        """Обрезка справа съедает как раз то, что различает воркtree."""
        names = [
            "-Users-me-Development-app--claude-worktrees-feature-alpha-apps-web",
            "-Users-me-Development-app--claude-worktrees-feature-beta-apps-web",
        ]
        labels = shorten_projects(names, width=30)
        assert labels[names[0]] != labels[names[1]]
        assert all(len(v) <= 30 for v in labels.values())

    def test_prefix_is_dropped_on_segment_boundaries(self):
        """Общий префикс `-Users-me-Development-app` не должен резать `apple`
        пополам, оставляя `le-...`."""
        names = [
            "-Users-me-Development-app",
            "-Users-me-Development-apple",
        ]
        labels = shorten_projects(names, width=46)
        assert set(labels.values()) == {"app", "apple"}

    def test_empty_input(self):
        assert shorten_projects([], width=46) == {}


@pytest.fixture
def root(tmp_path):
    """Два проекта и воркtree одного из них — как в реальном ~/.claude/projects."""
    for proj in ("-Users-me-alpha", "-Users-me-beta", "-Users-me-alpha-worktrees-x"):
        d = tmp_path / proj
        d.mkdir()
        (d / "s.jsonl").write_text(
            json.dumps({"message": {"content": f"OPENAI_API_KEY={FAKE_KEY}"}}) + "\n",
            encoding="utf-8",
        )
    return str(tmp_path)


class TestScanScope:
    """Скан ходит по всему ~/.claude/projects независимо от текущей папки —
    так и задумано, ключ из соседнего проекта живой ровно так же. Но без
    возможности сузить это читается как ошибка."""

    def test_without_a_filter_every_project_is_scanned(self, root):
        assert scan(root)["files"] == 3

    def test_filter_keeps_only_matching_projects(self, root):
        r = scan(root, project="beta")
        assert r["files"] == 1
        assert [p for p, _, _ in r["by_project"]] == ["-Users-me-beta"]

    def test_filter_is_a_substring_so_worktrees_come_along(self, root):
        assert scan(root, project="alpha")["files"] == 2

    def test_filter_matching_nothing_finds_nothing(self, root):
        r = scan(root, project="nosuchproject")
        assert r["files"] == 0
        assert r["occurrences"] == 0


class TestPrefilter:
    """Скан читает 1.9 ГБ и гонит по каждой строке все паттерны разом.
    Дешёвый предварительный отсев снимает основную массу, но обязан быть
    строго шире детектора: отбросив строку с секретом, он превращает
    оптимизацию в тихий пропуск.
    """

    def test_lets_through_everything_the_detector_finds(self):
        from detect import find_secrets
        from scanner import maybe_secret

        from test_detect import FAKE
        samples = list(FAKE.values()) + [
            "postgres://flowly:s3cr3tPassw0rd@10.0.0.4:5432/prod",
            "MCP_ZAPIS_CLIENT_ID=b3d9e21c74f8a05e6c1d4b27a9e83f60",
            "-----BEGIN RSA PRIVATE KEY-----",
            "DB_PASSWORD=7Hq2Wz9Kx4Lm8Pv3Nt6Rb1Yc5Fd0Gj",
            r"FOO=bar\nAPI_TOKEN=9Kx4Lm8Pv3Nt6Rb1Yc5Fd0GjQw2Ea",
            "TIKTOK_CLIENT_SECRET=aw3Kd9Xm2Pq7Lv5Rt8Yn1Zb4Hc6Jf0Gs",
        ]
        for s in samples:
            assert find_secrets(s), f"фикстура протухла: {s[:24]}"
            assert maybe_secret(s), f"префильтр съел находку: {s[:24]}"

    def test_rejects_ordinary_prose(self):
        from scanner import maybe_secret
        assert not maybe_secret("Давай посмотрим, что там в этом файле.")
        assert not maybe_secret("  return sorted(found, key=lambda f: f.start)")


class TestProgress:
    def test_reports_progress_up_to_the_total(self, root):
        seen = []
        scan(root, on_progress=lambda done, total: seen.append((done, total)))
        assert seen, "прогресс не вызывался"
        assert seen[-1] == (3, 3)
        assert all(t == 3 for _, t in seen)

    def test_progress_is_optional(self, root):
        assert scan(root)["files"] == 3


class TestProjectOf:
    def test_takes_the_top_level_directory(self, tmp_path):
        p = tmp_path / "-Users-me-proj" / "abc" / "session.jsonl"
        p.parent.mkdir(parents=True)
        p.write_text("{}", encoding="utf-8")
        assert project_of(str(p), str(tmp_path)) == "-Users-me-proj"


class TestMask:
    """`check` output is meant to be pasteable into a ticket, so a mask may
    name the key's format and its last 4 characters, never more."""

    def test_keeps_the_public_format_prefix(self):
        from scanner import mask
        assert mask("sk-proj-" + "a" * 44 + "WXYZ") == "sk-proj-…WXYZ"
        assert mask("ghp_" + "b" * 32 + "WXYZ") == "ghp_…WXYZ"

    def test_reveals_at_most_four_characters_of_the_secret(self):
        from scanner import mask
        secret = "Zq8" + "c" * 30 + "WXYZ"
        shown = mask(secret).replace("…", "")
        assert shown == "WXYZ"

    def test_short_secrets_reveal_nothing(self):
        from scanner import mask
        assert mask("hunter2hunter2hunt") == "…"
        assert mask("sk-proj-short") == "sk-proj-…"
