"""Токенизация и матчер «пережило ли сообщение саммари».

Цитаты в тестах — реальные, из секции 6 саммари сессии 87d0d0e5 (contentgen).
Суммаризатор цитирует пользователя дословно, вместе с опечатками, поэтому
сильным признаком сохранности считается совпадение n-граммы, а не общий словарь.
"""

from recall import content_tokens, is_instruction, quoted_in, token_recall


class TestContentTokens:
    def test_lowercases_and_drops_punctuation(self):
        assert content_tokens("Почини Биллинг!") == {"почини", "биллинг"}

    def test_drops_russian_stopwords(self):
        assert "это" not in content_tokens("это надо переписать")
        assert "переписать" in content_tokens("это надо переписать")

    def test_drops_english_stopwords(self):
        assert "the" not in content_tokens("fix the handler")
        assert "handler" in content_tokens("fix the handler")

    def test_drops_tokens_shorter_than_three_chars(self):
        assert content_tokens("go до дом") == {"дом"}

    def test_splits_dotted_filename_into_parts(self):
        assert "subscription" in content_tokens("посмотри subscription.ts")

    def test_keeps_screaming_snake_identifier(self):
        assert "openai_api_key" in content_tokens("OPENAI_API_KEY стоит в env")


class TestIsInstruction:
    def test_short_acknowledgement_is_not_an_instruction(self):
        assert is_instruction("дальше") is False
        assert is_instruction("да го продолжай") is False

    def test_message_with_enough_content_words_is_an_instruction(self):
        assert is_instruction("не трогай миграции они катятся отдельно") is True


class TestQuotedIn:
    def test_verbatim_quote_counts_as_quoted(self):
        msg = "првоерь логи почему то посты threads не выходят"
        summary = '- "првоерь логи почему то посты threads не выходят" (with screenshot)'
        assert quoted_in(msg, summary) is True

    def test_unrelated_text_is_not_quoted(self):
        msg = "не трогай миграции они катятся отдельно"
        summary = "3. Files and Code Sections: subscription.ts, webhook.ts"
        assert quoted_in(msg, summary) is False

    def test_scattered_shared_words_are_not_a_quote(self):
        msg = "перепиши обработчик подписок целиком"
        summary = "обработчик вебхуков; отдельно правились подписок лимиты; перепиши тесты"
        assert quoted_in(msg, summary) is False


class TestTokenRecall:
    def test_identical_text_scores_one(self):
        assert token_recall("почини обработчик подписок", "почини обработчик подписок") == 1.0

    def test_absent_text_scores_zero(self):
        assert token_recall("почини обработчик подписок", "совершенно другой текст") == 0.0

    def test_paraphrase_scores_between(self):
        score = token_recall(
            "не трогай миграции они катятся отдельно",
            "Пользователь просил не трогать миграции",
        )
        assert 0.0 < score < 1.0

    def test_empty_message_scores_zero_instead_of_dividing_by_zero(self):
        assert token_recall("и в на", "любой текст") == 0.0
