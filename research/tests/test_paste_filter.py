"""Отделение того, что человек напечатал, от того, что он вставил.

Прогон по 53 компакциям показал: без этого фильтра в «потерянные указания»
попадают дампы docker/ssh и текст со страниц Meta и Reddit. Саммари их не
цитирует — и правильно делает, это не указания.

Фильтр намеренно консервативен: он скорее выбросит настоящее указание,
чем засчитает вставку. Итоговое число из-за этого — нижняя граница потерь.
"""

from recall import instruction_text, is_instruction

SHELL_DUMP = """root@ubuntu-s-4vcpu-8gb-fra1-01:~# docker stats --no-stream
NAME        CPU %     MEM USAGE / LIMIT
core        0.15%     412MiB / 7.77GiB
worker      0.03%     122MiB / 7.77GiB"""


class TestInstructionText:
    def test_shell_prompt_line_is_dropped_but_question_survives(self):
        text = SHELL_DUMP + "\nпрвоерь логи почему то посты threads не выходят"
        assert instruction_text(text) == "првоерь логи почему то посты threads не выходят"

    def test_plain_typed_message_is_untouched(self):
        text = "не трогай миграции они катятся отдельно"
        assert instruction_text(text) == text

    def test_ssh_session_paste_leaves_nothing(self):
        text = "flowlyai@MacBook-Pro % ssh root@129.212.171.222\nroot@129.212.171.222's password:"
        assert instruction_text(text) == ""

    def test_tab_separated_output_is_dropped(self):
        text = "NAME\tCPU\tMEM\ncore\t0.15%\t412MiB\nпочему воркер жрёт память"
        assert instruction_text(text) == "почему воркер жрёт память"


class TestIsInstruction:
    def test_pure_terminal_dump_is_not_an_instruction(self):
        assert is_instruction(SHELL_DUMP) is False

    def test_dump_with_appended_question_is_an_instruction(self):
        assert is_instruction(SHELL_DUMP + "\nпочему воркер жрёт столько памяти") is True

    def test_long_pasted_document_is_not_an_instruction(self):
        pasted = (
            "In order to create an application or use our API you can read our full "
            "policies here. Please describe your reason for this submission. "
        ) * 6
        assert is_instruction(pasted) is False

    def test_short_typed_instruction_is_an_instruction(self):
        assert is_instruction("не трогай миграции они катятся отдельно") is True

    def test_short_acknowledgement_is_still_not_an_instruction(self):
        assert is_instruction("дальше") is False


class TestCommandLines:
    def test_bare_command_without_prompt_is_dropped(self):
        text = "swapon --show\ndocker stats --no-stream\nпочему своп забит"
        assert instruction_text(text) == "почему своп забит"

    def test_piped_continuation_is_dropped(self):
        text = (
            "docker logs --since 30m flowly-core 2>&1 \\\n"
            "  | grep -iE 'slot|book|admin'\n"
            "почему записи не создаются"
        )
        assert instruction_text(text) == "почему записи не создаются"

    def test_banner_line_is_dropped(self):
        text = "=== KASPI SESSION PROBE (read-only) ===\nчто с сессией"
        assert instruction_text(text) == "что с сессией"

    def test_python_traceback_is_dropped(self):
        text = (
            "Traceback (most recent call last):\n"
            "  File \"app.py\", line 12, in <module>\n"
            "ProgrammingError: relation does not exist\n"
            "почини схему обзора"
        )
        assert instruction_text(text) == "почини схему обзора"

    def test_prose_mentioning_docker_is_kept(self):
        text = "надо переписать docker compose под новый воркер"
        assert instruction_text(text) == text

    def test_pure_command_paste_is_not_an_instruction(self):
        text = "swapon --show\ndocker stats --no-stream --format 'table {{.Name}}'"
        assert is_instruction(text) is False


class TestStructuredPaste:
    def test_env_assignment_is_dropped(self):
        text = "MCP_ZAPIS_CLIENT_ID=b3d9e21c74f8a05e6c1d4b27a9e83f60\nдобавь эти креды в конфиг"
        assert instruction_text(text) == "добавь эти креды в конфиг"

    def test_json_fragment_is_dropped(self):
        text = "-d '{\"filter\":{\"PHONE\":\"+7775\"},\"select\":[\"ID\"]}'\nпочему битрикс не отдаёт контакт"
        assert instruction_text(text) == "почему битрикс не отдаёт контакт"

    def test_long_hex_identifier_line_is_dropped(self):
        text = "target key : kaspi:session:f8ef62654c8d5174a4173f71abf4c3b2\nчто с этой сессией"
        assert instruction_text(text) == "что с этой сессией"

    def test_prose_with_filename_is_kept(self):
        text = "посмотри subscription.ts там ретраи сломаны"
        assert instruction_text(text) == text

    def test_prose_with_url_is_kept(self):
        text = "смотри https://developers.facebook.com/docs/instagram там описан гейт"
        assert instruction_text(text) == text
