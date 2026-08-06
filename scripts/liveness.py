"""Проверка, живы ли найденные ключи.

Это единственная часть buzzcut, которая ходит в сеть, и единственная, которая
работает с самим значением секрета. Поэтому:

  · запускается только по явному согласию (`buzzcut check --yes`);
  · ключ уходит ровно одному адресату — его собственному провайдеру;
  · используются только read-only эндпоинты (список моделей, профиль);
  · никакой телеметрии, никаких третьих сторон.

Смысл в том, что 1223 совпадения и «три ключа, которыми можно
воспользоваться прямо сейчас» — разные новости. Первое игнорируют, второе нет.
"""

import json
import urllib.error
import urllib.request

TIMEOUT = 10

LIVE, DEAD, UNKNOWN, MANUAL = "live", "dead", "unknown", "manual"

# Эндпоинты выбраны так, чтобы ничего не менять и не тарифицироваться.
PROBES = {
    "openai": ("https://api.openai.com/v1/models",
               lambda k: {"Authorization": f"Bearer {k}"}),
    "anthropic": ("https://api.anthropic.com/v1/models",
                  lambda k: {"x-api-key": k, "anthropic-version": "2023-06-01"}),
    "github": ("https://api.github.com/user",
               lambda k: {"Authorization": f"Bearer {k}",
                          "Accept": "application/vnd.github+json"}),
    "slack": ("https://slack.com/api/auth.test",
              lambda k: {"Authorization": f"Bearer {k}"}),
}

# У этих проверка либо требует подписи запроса, либо означает коннект
# к боевой инфраструктуре пользователя. Решает человек.
MANUAL_KINDS = {"aws", "google", "telegram", "private_key", "url_credentials",
                "env_secret", "jwt"}


def check_key(kind, value):
    """LIVE / DEAD / UNKNOWN / MANUAL для одного ключа."""
    if kind in MANUAL_KINDS or kind not in PROBES:
        return MANUAL

    url, headers = PROBES[kind]
    req = urllib.request.Request(url, headers=headers(value), method="GET")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if kind == "slack":
                # Slack отвечает 200 и на протухший токен — смотрим тело
                body = json.loads(resp.read(4096) or b"{}")
                return LIVE if body.get("ok") else DEAD
            return LIVE if resp.status == 200 else UNKNOWN
    except urllib.error.HTTPError as e:
        return DEAD if e.code in (401, 403) else UNKNOWN
    except Exception:
        return UNKNOWN
