import hashlib
import hmac
import os
import secrets
import sqlite3
import uuid as uuid_mod
from datetime import datetime, timezone

import config

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
        return conn.execute("SELECT * FROM accounts WHERE id = ?", (cur.lastrowid,)).fetchone()
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