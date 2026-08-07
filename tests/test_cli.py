"""Отрисовка прогресса.

Полосу легко «проверить» глазами один раз и считать сделанной. Здесь
закреплено то, что глаз не ловит: под не-TTY не должно уходить ни байта
(иначе полоса засоряет пайпы и логи), кадры не должны идти на каждый файл
из четырёх тысяч, а последний обязан затереть за собой строку — иначе
отчёт печатается поверх недоеденной полосы.

Поток передаётся аргументом, а не подменой `sys.stderr`: pytest
переустанавливает глобальный `sys.stderr` между настройкой фикстуры и телом
теста, из-за чего подмена молча не доживает до проверки, а тест зеленеет
или краснеет в зависимости от флага `-s`.
"""

import io

from buzzcut import _progress


class Screen(io.StringIO):
    """Терминал (isatty=True) или пайп (False)."""

    def __init__(self, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty

    def frames(self):
        return [f.strip() for f in self.getvalue().split("\r") if "scanning" in f]

    def run(self, total):
        for done in range(1, total + 1):
            _progress(done, total, stream=self)
        return self


class TestWritesOnlyToATerminal:
    def test_a_pipe_gets_nothing(self):
        assert Screen(tty=False).run(220).getvalue() == ""

    def test_a_terminal_gets_frames(self):
        assert Screen(tty=True).run(220).frames()


class TestThrottling:
    def test_one_frame_per_fifty_files_plus_the_final_one(self):
        assert len(Screen(tty=True).run(220).frames()) == 5   # 50 100 150 200 220

    def test_frames_read_correctly(self):
        f = Screen(tty=True).run(220).frames()
        assert f[0] == "scanning… 50/220 · 22%"
        assert f[-1] == "scanning… 220/220 · 100%"

    def test_a_short_run_still_reports_completion(self):
        """Меньше пятидесяти файлов — промежуточных кадров нет, но финальный
        обязан быть, иначе прогресс молчит там, где он дешевле всего."""
        f = Screen(tty=True).run(3).frames()
        assert f == ["scanning… 3/3 · 100%"]

    def test_a_single_file_does_not_divide_by_zero(self):
        assert Screen(tty=True).run(1).frames() == ["scanning… 1/1 · 100%"]


class TestCleansUpAfterItself:
    def test_the_last_frame_erases_the_line(self):
        s = Screen(tty=True).run(220)
        assert s.getvalue().split("\r")[-1].strip() == ""

    def test_the_report_does_not_land_on_top_of_the_bar(self):
        s = Screen(tty=True).run(3)
        assert "scanning" not in s.getvalue().split("\r")[-1]
