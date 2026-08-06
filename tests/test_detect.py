"""Детектор секретов.

Два класса ошибок несимметричны по цене:
  · пропуск  — секрет утекает в транскрипт (плохо, но статус-кво);
  · ложное срабатывание — хук режет НЕ секрет, агент получает битые данные
    и начинает чинить несуществующую проблему (хуже: ломает работу).

Поэтому тестов на «не находить» здесь больше, чем на «находить».
Формы взяты из реальных транскриптов ~/.claude/projects (4306 файлов).
"""

from detect import find_secrets, redact


def _fake(prefix, body):
    """Фикстура собирается в рантайме.

    Целого токена в исходнике быть не должно: GitHub push protection и
    gitleaks сканируют файлы по форме, и репозиторий инструмента против
    секретов, заблокированный за секреты в собственных тестах, — не то,
    что хочется объяснять. Для детектора форма сохраняется полностью.
    """
    return prefix + body


FAKE = {
    "openai":    _fake("sk-" + "proj-", "QZ7tRvKeq7xK2mZp9vLbT4dRfA8sYcXe"),
    "anthropic": _fake("sk-" + "ant-", "api03-x7Kq2mZp9vLbT4dRfA8s"),
    "github":    _fake("ghp" + "_", "4mK2x7QpL9vB3nR8tY6wE1zA5cD0fG7hJ2kM"),
    "aws":       _fake("AKI" + "A", "IOSFODNN7EXAMPLE"),
    "google":    _fake("AIz" + "a", "SyB1k2M9pQ7rT4vX8zC3nF6hJ0lW5yA2bE"),
    "slack":     _fake("xox" + "b-", "2451234567-2451234567-AbCdEfGhIjKlMnOp"),
    "jwt":       _fake("eyJhbGciOiJIUzI1NiJ9." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
                       "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"),
}


def kinds(text):
    return sorted(f.kind for f in find_secrets(text))


def values(text):
    return [f.value for f in find_secrets(text)]


class TestProviderTokens:
    def test_openai_project_key(self):
        assert kinds(f"OPENAI_API_KEY={FAKE['openai']}") == ["openai"]

    def test_anthropic_key(self):
        assert kinds(f"export ANTHROPIC_API_KEY={FAKE['anthropic']}") == ["anthropic"]

    def test_github_pat(self):
        assert kinds(f"token: {FAKE['github']}") == ["github"]

    def test_aws_access_key_id(self):
        assert kinds(f"aws_access_key_id = {FAKE['aws']}") == ["aws"]

    def test_google_api_key(self):
        assert kinds(f"key={FAKE['google']}") == ["google"]

    def test_slack_bot_token(self):
        assert kinds(FAKE["slack"]) == ["slack"]

    def test_private_key_header(self):
        assert kinds("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...") == ["private_key"]


class TestStructuralSecrets:
    def test_credentials_in_url(self):
        assert kinds("postgres://flowly:s3cr3tPassw0rd@10.0.0.4:5432/prod") == ["url_credentials"]

    def test_jwt(self):
        assert kinds(FAKE["jwt"]) == ["jwt"]

    def test_env_assignment_with_high_entropy_value(self):
        assert kinds("MCP_ZAPIS_CLIENT_ID=b3d9e21c74f8a05e6c1d4b27a9e83f60") == ["env_secret"]


class TestMustNotMatch:
    """Ложное срабатывание ломает работу агента. Ничего из этого не режем."""

    def test_empty_assignment(self):
        assert find_secrets("OPENAI_API_KEY=") == []

    def test_already_redacted(self):
        assert find_secrets("OPENAI_API_KEY=***REDACTED***") == []

    def test_placeholder_words(self):
        assert find_secrets("API_KEY=your_api_key_here") == []
        assert find_secrets("PASSWORD=changeme") == []
        assert find_secrets("TOKEN=xxxxxxxxxxxxxxxxxxxx") == []

    def test_shell_variable_reference(self):
        assert find_secrets("API_KEY=$OPENAI_KEY") == []
        assert find_secrets("API_KEY=${OPENAI_KEY}") == []

    def test_angle_bracket_placeholder(self):
        assert find_secrets("API_KEY=<your-key-here>") == []

    def test_docs_ellipsis_key(self):
        assert find_secrets("Use sk-ant-... as your key") == []

    def test_low_entropy_english_value(self):
        assert find_secrets("DATABASE_PASSWORD=correcthorsebatterystaple") == []

    def test_url_without_password(self):
        assert find_secrets("postgres://localhost:5432/dev") == []
        assert find_secrets("https://github.com/akzh4n/buzzcut") == []

    def test_env_var_name_alone(self):
        assert find_secrets("проверь, стоит ли OPENAI_API_KEY в окружении") == []

    def test_git_sha_is_not_a_secret(self):
        assert find_secrets("commit f519c397a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6") == []


class TestRedact:
    def test_replaces_only_the_value(self):
        out = redact(f"OPENAI_API_KEY={FAKE['openai']}")
        assert FAKE["openai"] not in out
        assert out.startswith("OPENAI_API_KEY=")
        assert "REDACTED" in out

    def test_keeps_surrounding_text_intact(self):
        out = redact(f"line one\nAWS_KEY={FAKE['aws']}\nline three")
        assert out.startswith("line one\n")
        assert out.endswith("\nline three")

    def test_text_without_secrets_is_returned_unchanged(self):
        text = "npm run build && npx tsc --noEmit"
        assert redact(text) is text

    def test_marks_which_provider_was_cut(self):
        assert "openai" in redact(f"k={FAKE['openai']}")


class TestEnvNameGate:
    """Прогон по 4306 реальным файлам показал: значение само по себе секрет
    не отличает. `PYTHONPATH=/a/b:/c` и `CORE_INTERNAL_SECRET=<hex>` устроены
    одинаково. Решает имя переменной.
    """

    def test_pythonpath_is_not_a_secret(self):
        assert find_secrets("PYTHONPATH=/Users/f/proj/backend:/Users/f/proj/lib") == []

    def test_worktree_path_var_is_not_a_secret(self):
        assert find_secrets("WT2=/Users/flowlyai/Desktop/Development/flowly/.worktrees/DEV-604") == []

    def test_git_ref_var_is_not_a_secret(self):
        assert find_secrets("HEAD=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0") == []

    def test_scratch_dir_var_is_not_a_secret(self):
        assert find_secrets("SCRATCH=/private/tmp/claude-501/x8f2a9c1/scratchpad") == []

    def test_secret_named_var_is_a_secret(self):
        assert kinds("CORE_INTERNAL_SECRET=8f2a9c1d7e3b5a4f6091c2d8e7b3a5f4") == ["env_secret"]

    def test_client_secret_is_a_secret(self):
        assert kinds("TIKTOK_CLIENT_SECRET=aw3Kd9Xm2Pq7Lv5Rt8Yn1Zb4Hc6Jf0Gs") == ["env_secret"]

    def test_environment_key_is_a_secret(self):
        assert kinds("ANTHROPIC_ENVIRONMENT_KEY=oat01x7Kq2mZp9vLbT4dRfA8sYcXe3W") == ["env_secret"]

    def test_password_var_is_a_secret(self):
        assert kinds("DB_PASSWORD=7Hq2Wz9Kx4Lm8Pv3Nt6Rb1Yc5Fd0Gj") == ["env_secret"]
