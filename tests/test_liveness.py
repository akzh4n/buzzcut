"""Reading a provider's answer.

The dangerous mistake is calling a working key dead: the report then says
"already rotated, just clean it out" about a key an attacker can still use.
401 means the provider does not know the key. 403 means it knows the key and
refuses this endpoint (restricted key, region, rate limit) — the key is live.
"""

import io
import urllib.error

import pytest

import liveness
from liveness import DEAD, LIVE, MANUAL, UNKNOWN, check_key


def answer(monkeypatch, status=None, error=None, body=b"{}"):
    class Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake_urlopen(req, timeout):
        if error is not None:
            raise error
        r = Resp(body)
        r.status = status
        return r

    monkeypatch.setattr(liveness.urllib.request, "urlopen", fake_urlopen)


def http_error(code):
    return urllib.error.HTTPError("https://x", code, "", {}, None)


@pytest.mark.parametrize("kind", ["openai", "anthropic", "github"])
class TestHttpProviders:
    def test_200_is_live(self, monkeypatch, kind):
        answer(monkeypatch, status=200)
        assert check_key(kind, "k") == LIVE

    def test_401_is_dead(self, monkeypatch, kind):
        answer(monkeypatch, error=http_error(401))
        assert check_key(kind, "k") == DEAD

    def test_403_is_live_not_dead(self, monkeypatch, kind):
        answer(monkeypatch, error=http_error(403))
        assert check_key(kind, "k") == LIVE

    def test_server_error_is_unknown(self, monkeypatch, kind):
        answer(monkeypatch, error=http_error(500))
        assert check_key(kind, "k") == UNKNOWN

    def test_network_failure_is_unknown(self, monkeypatch, kind):
        answer(monkeypatch, error=OSError("offline"))
        assert check_key(kind, "k") == UNKNOWN


class TestSlack:
    def test_ok_false_is_dead_even_on_200(self, monkeypatch):
        answer(monkeypatch, status=200, body=b'{"ok": false}')
        assert check_key("slack", "k") == DEAD

    def test_ok_true_is_live(self, monkeypatch):
        answer(monkeypatch, status=200, body=b'{"ok": true}')
        assert check_key("slack", "k") == LIVE


class TestNeverProbed:
    @pytest.mark.parametrize("kind", ["aws", "google", "private_key",
                                      "url_credentials", "env_secret", "jwt"])
    def test_left_to_the_human_without_a_request(self, monkeypatch, kind):
        answer(monkeypatch, error=AssertionError("must not touch the network"))
        assert check_key(kind, "k") == MANUAL
