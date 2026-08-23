import hashlib
import hmac
import json
import logging
import os
import secrets
import sqlite3
import threading
import urllib.request
import uuid as uuid_mod
from datetime import datetime, timezone

import config

log = logging.getLogger("db")

GIST_FILE = "accounts.json"


def _bk_cfg():
    return os.environ.get("GH_TOKEN"), os.environ.get("GH_REPO")


def _bk_request(url, data=None, method="GET"):
    token, _ = _bk_cfg()
    req = urllib.request.Request(url, method=method)
    req.add_header("Authorization", "Bearer " + token)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "politland-auth")
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, body, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _accounts_payload():
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT nickname, password_hash, uuid, telegram_id, created_at FROM accounts ORDER BY id"
        ).fetchall()
        return json.dumps({"accounts": [dict(r) for r in rows]}, ensure_ascii=False)
    finally:
        conn.close()


def backup_to_gist_async():
    """Сохраняет все аккаунты в приватный репозиторий — переживает деплои Render."""
    t = threading.Thread(target=_backup_to_repo, daemon=True)
    t.start()


def _backup_to_repo():
    try:
        token, repo = _bk_cfg()
        if not token or not repo:
            return
        content = _accounts_payload()
        n = len(json.loads(content)["accounts"])
        path = "https://api.github.com/repos/" + repo + "/contents/" + GIST_FILE
        sha = None
        try:
            sha = _bk_request(path + "?ref=main").get("sha")
        except Exception:
            sha = None
        import base64

        payload = {
            "message": "accounts backup",
            "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
        }
        if sha:
            payload["sha"] = sha
        _bk_request(path, payload, method="PUT")
        log.info("accounts backed up to github (%s accounts)", n)
    except Exception as e:
        log.warning("github backup failed: %s", e)


def restore_from_gist():
    """Если база пуста (свежий деплой) — восстанавливает аккаунты из бэкапа."""
    try:
        token, repo = _bk_cfg()
        if not token or not repo:
            return
        conn = _connect()
        try:
            cnt = conn.execute("SELECT COUNT(*) AS c FROM accounts").fetchone()["c"]
        finally:
            conn.close()
        if cnt:
            return
        import base64

        path = "https://api.github.com/repos/" + repo + "/contents/" + GIST_FILE + "?ref=main"
        f = _bk_request(path)
        raw = base64.b64decode(f.get("content", "")).decode("utf-8") if f else None
        if not raw:
            return
        accs = json.loads(raw).get("accounts", [])
        if not accs:
            return
        conn = _connect()
        try:
            for a in accs:
                conn.execute(
                    "INSERT OR IGNORE INTO accounts (nickname, password_hash, uuid, telegram_id, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (
                        a.get("nickname"),
                        a.get("password_hash"),
                        a.get("uuid"),
                        a.get("telegram_id"),
                        a.get("created_at") or _now(),
                    ),
                )
            conn.commit()
        finally:
            conn.close()
        log.info("restored %s accounts from github backup", len(accs))
    except Exception as e:
        log.warning("github restore failed: %s", e)


PBKDF2_ITERATIONS = 120_000


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect():
    conn = sqlite3.connect(config.db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nickname TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            uuid TEXT NOT NULL UNIQUE,
            telegram_id INTEGER,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            access_token TEXT PRIMARY KEY,
            client_token TEXT NOT NULL,
            account_id INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS skins (
            account_id INTEGER PRIMARY KEY,
            hash TEXT NOT NULL,
            model TEXT NOT NULL DEFAULT 'default',
            updated_at TEXT NOT NULL
        );
        """
    )
    conn.commit()
    conn.close()
    restore_from_gist()


def hash_password(password):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return salt.hex() + "$" + dk.hex()


def verify_password(password, stored):
    try:
        salt_hex, expected = stored.split("$", 1)
        salt = bytes.fromhex(salt_hex)
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return hmac.compare_digest(dk.hex(), expected)


def create_account(nickname, password, telegram_id=None):
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO accounts (nickname, password_hash, uuid, telegram_id, created_at) VALUES (?, ?, ?, ?, ?)",
            (nickname, hash_password(password), str(uuid_mod.uuid4()), telegram_id, _now()),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM accounts WHERE id = ?", (cur.lastrowid,)).fetchone()
        backup_to_gist_async()
        return row
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()


def nickname_taken(nickname):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT id FROM accounts WHERE lower(nickname) = lower(?)", (nickname,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def get_account_by_nickname(nickname):
    conn = _connect()
    try:
        return conn.execute(
            "SELECT * FROM accounts WHERE lower(nickname) = lower(?)", (nickname,)
        ).fetchone()
    finally:
        conn.close()


def get_account_by_telegram(telegram_id):
    conn = _connect()
    try:
        return conn.execute(
            "SELECT * FROM accounts WHERE telegram_id = ?", (telegram_id,)
        ).fetchone()
    finally:
        conn.close()


def get_account_by_uuid(uuid_str):
    norm = uuid_str.replace("-", "").lower()
    conn = _connect()
    try:
        rows = conn.execute("SELECT * FROM accounts").fetchall()
        for row in rows:
            if row["uuid"].replace("-", "").lower() == norm:
                return row
        return None
    finally:
        conn.close()


def change_password(account_id, new_password):
    conn = _connect()
    try:
        conn.execute(
            "UPDATE accounts SET password_hash = ? WHERE id = ?",
            (hash_password(new_password), account_id),
        )
        conn.commit()
        backup_to_gist_async()
    finally:
        conn.close()


def create_session(account_id, client_token=None):
    token = secrets.token_hex(16)
    if not client_token:
        client_token = secrets.token_hex(16)
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO sessions (access_token, client_token, account_id, created_at) VALUES (?, ?, ?, ?)",
            (token, client_token, account_id, _now()),
        )
        conn.commit()
    finally:
        conn.close()
    return token


def get_session(access_token):
    conn = _connect()
    try:
        return conn.execute(
            "SELECT s.*, a.nickname, a.uuid, a.telegram_id FROM sessions s JOIN accounts a ON a.id = s.account_id WHERE s.access_token = ?",
            (access_token,),
        ).fetchone()
    finally:
        conn.close()


def rotate_session(old_token):
    new_token = secrets.token_hex(16)
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT access_token FROM sessions WHERE access_token = ?", (old_token,)
        ).fetchone()
        if row is None:
            return None
        conn.execute(
            "UPDATE sessions SET access_token = ? WHERE access_token = ?",
            (new_token, old_token),
        )
        conn.commit()
        return new_token
    finally:
        conn.close()


def delete_session(access_token):
    conn = _connect()
    try:
        conn.execute("DELETE FROM sessions WHERE access_token = ?", (access_token,))
        conn.commit()
    finally:
        conn.close()


def delete_sessions_for_account(account_id):
    conn = _connect()
    try:
        conn.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
        conn.commit()
    finally:
        conn.close()


def skins_dir():
    d = os.path.join(config.BASE_DIR, "skins")
    os.makedirs(d, exist_ok=True)
    return d


def skin_file(skin_hash):
    return os.path.join(skins_dir(), skin_hash + ".png")


def set_skin(account_id, png_bytes, model="default"):
    """Сохраняет PNG на диск под именем-хэшем и пишет запись в БД.

    Возвращает hash. Старый файл скина удаляется, если на него больше никто
    не ссылается.
    """
    if model not in ("default", "slim"):
        model = "default"
    skin_hash = hashlib.sha256(png_bytes).hexdigest()[:32]
    with open(skin_file(skin_hash), "wb") as f:
        f.write(png_bytes)
    conn = _connect()
    try:
        old = conn.execute(
            "SELECT hash FROM skins WHERE account_id = ?", (account_id,)
        ).fetchone()
        conn.execute(
            "INSERT INTO skins (account_id, hash, model, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(account_id) DO UPDATE SET hash = excluded.hash, "
            "model = excluded.model, updated_at = excluded.updated_at",
            (account_id, skin_hash, model, _now()),
        )
        conn.commit()
        if old is not None and old["hash"] != skin_hash:
            still_used = conn.execute(
                "SELECT 1 FROM skins WHERE hash = ?", (old["hash"],)
            ).fetchone()
            if still_used is None:
                try:
                    os.remove(skin_file(old["hash"]))
                except OSError:
                    pass
        return skin_hash
    finally:
        conn.close()


def get_skin(account_id):
    conn = _connect()
    try:
        return conn.execute(
            "SELECT * FROM skins WHERE account_id = ?", (account_id,)
        ).fetchone()
    finally:
        conn.close()


def delete_skin(account_id):
    conn = _connect()
    try:
        row = conn.execute(
            "SELECT hash FROM skins WHERE account_id = ?", (account_id,)
        ).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM skins WHERE account_id = ?", (account_id,))
        conn.commit()
        still_used = conn.execute(
            "SELECT 1 FROM skins WHERE hash = ?", (row["hash"],)
        ).fetchone()
        if still_used is None:
            try:
                os.remove(skin_file(row["hash"]))
            except OSError:
                pass
        return True
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print("DB ready at", config.db_path())