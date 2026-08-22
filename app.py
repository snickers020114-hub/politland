"""Точка входа для облачного хостинга (Render): HTTP-сервер + Telegram-бот
в одном процессе, порт берётся из переменной окружения PORT."""
import asyncio
import logging
import os
import threading
import time
import urllib.request

from aiohttp import web

import config
import db
import server

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("app")


def _self_ping():
    """Пингует свой публичный URL каждые 5 минут — бесплатный тариф Render
    засыпает после ~15 минут без входящих запросов."""
    url = (os.environ.get("RENDER_EXTERNAL_URL") or config.get("public_url") or "").rstrip("/")
    if not url or "onrender.com" not in url:
        return
    while True:
        time.sleep(300)
        try:
            urllib.request.urlopen(url + "/", timeout=15).read()
        except Exception as e:
            log.warning("self-ping failed: %s", e)


async def run():
    db.init_db()
    app = server.build_app()
    # runner.setup() выполняет on_startup сервера (db.init_db + запись auth_server.json)
    runner = web.AppRunner(app)
    await runner.setup()
    host = config.get("host")
    port = int(config.get("port"))
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()
    log.info("HTTP ready at http://%s:%s (public: %s)", host, port, config.get("public_url"))

    threading.Thread(target=_self_ping, daemon=True).start()

    from bot import main as bot_main
    await bot_main()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except (KeyboardInterrupt, SystemExit):
        pass