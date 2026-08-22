import json
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

DEFAULTS = {
    "bot_token": "",
    "host": "0.0.0.0",
    "port": 25500,
    "public_url": "http://127.0.0.1:25500",
    # Локальная папка Minecraft-сервера: только для домашнего ПК,
    # на хостинге остаётся пустой и раздел «Minecraft-сервер» скрыт.
    "mc_server_dir": "",
}

_config = None


def load():
    global _config
    cfg = dict(DEFAULTS)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
                cfg.update(json.load(f))
        except Exception as e:
            print(f"[config] failed to load {CONFIG_PATH}: {e}")
    # Переменные окружения (для облачного хостинга) важнее файла
    if os.environ.get("BOT_TOKEN"):
        cfg["bot_token"] = os.environ["BOT_TOKEN"]
    if os.environ.get("ADMIN_PASSWORD"):
        cfg["admin_password"] = os.environ["ADMIN_PASSWORD"]
    if os.environ.get("RENDER_EXTERNAL_URL"):
        cfg["public_url"] = os.environ["RENDER_EXTERNAL_URL"]
    elif os.environ.get("PUBLIC_URL"):
        cfg["public_url"] = os.environ["PUBLIC_URL"]
    if os.environ.get("PORT"):
        try:
            cfg["port"] = int(os.environ["PORT"])
        except ValueError:
            pass
    _config = cfg
    return _config


def get(key):
    if _config is None:
        load()
    return _config.get(key, DEFAULTS.get(key))


def save(cfg):
    global _config
    _config = cfg
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)


def db_path():
    return os.path.join(BASE_DIR, "accounts.db")


def launcher_appdata_dirs():
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return []
    return [
        os.path.join(appdata, "Polite Land"),
        os.path.join(appdata, "frogLauncher"),
    ]


def write_launcher_auth_config():
    # создаём конфиг только если его ещё нет: у каждого свой адрес
    # (у владельца локальный 127.0.0.1, у друзей — публичный из установщика)
    payload = json.dumps({"server": get("public_url")}, ensure_ascii=False)
    for d in launcher_appdata_dirs():
        try:
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, "auth_server.json")
            if os.path.exists(p):
                continue
            with open(p, "w", encoding="utf-8") as f:
                f.write(payload)
        except Exception as e:
            print(f"[config] cannot write launcher auth config to {d}: {e}")


def main():
    load()
    print(json.dumps(_config, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()