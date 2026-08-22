import asyncio
import base64
import hashlib
import json
import logging
import os
import shutil
import struct
import subprocess
import sys
import time

from aiohttp import web
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import config
import db
import mcserver
import mods
import pack

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("auth")

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS, PUT, DELETE",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}

KEY_FILE = os.path.join(config.BASE_DIR, "signing_key.pem")

# Скины: 64x64 (или legacy 64x32), PNG, до 256 КБ
MAX_SKIN_BYTES = 256 * 1024
ALLOWED_SKIN_SIZES = ((64, 64), (64, 32), (128, 128), (256, 256), (512, 512))

# serverId -> {"name": str, "uuid": str, "expires": float}
join_sessions = {}


def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    try:
        with open(KEY_FILE, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    except OSError as e:
        log.warning("Cannot persist signing key: %s", e)
    return key


def public_key_pem():
    key = load_or_create_key()
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _public_host():
    """Хост из public_url — для skinDomains в метаданных authlib-injector."""
    url = config.get("public_url")
    host = url.split("://", 1)[-1].split("/", 1)[0]
    return host.split(":", 1)[0]


def _cors_response(status=204):
    return web.Response(status=status, headers=CORS_HEADERS)


def _png_dimensions(data):
    """Возвращает (width, height) для PNG или None, если это не PNG."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    if data[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def _sign(payload_b64):
    key = load_or_create_key()
    signature = key.sign(
        payload_b64.encode("utf-8"), padding.PKCS1v15(), hashes.SHA1()
    )
    return base64.b64encode(signature).decode("ascii")


def _textures_property(account, request):
    """Собирает property `textures` профиля (с подписью), если скин загружен."""
    skin = db.get_skin(account["id"])
    if skin is None:
        return None
    base = config.get("public_url").rstrip("/")
    texture = {"url": f"{base}/textures/{skin['hash']}"}
    if skin["model"] == "slim":
        texture["metadata"] = {"model": "slim"}
    payload = {
        "timestamp": int(time.time() * 1000),
        "profileId": account["uuid"].replace("-", ""),
        "profileName": account["nickname"],
        "textures": {"SKIN": texture},
    }
    value = base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return {"name": "textures", "value": value, "signature": _sign(value)}



async def _read_body(request):
    try:
        raw = await request.read()
    except Exception:
        raw = b""
    text = raw.decode("utf-8-sig", "replace").strip()
    if text:
        try:
            return json.loads(text)
        except Exception:
            pass
    try:
        data = await request.post()
        return dict(data)
    except Exception:
        return {}


def _error(message):
    return web.json_response(
        {"error": "ForbiddenOperationException", "errorMessage": message},
        status=403,
        headers=CORS_HEADERS,
    )


def _profile(account):
    return {
        "id": account["uuid"].replace("-", ""),
        "name": account["nickname"],
    }


def _auth_payload(account, access_token, client_token):
    return {
        "accessToken": access_token,
        "clientToken": client_token,
        "availableProfiles": [_profile(account)],
        "selectedProfile": _profile(account),
        "user": {"id": account["uuid"].replace("-", ""), "properties": []},
    }


def _full_profile(account, request=None):
    """Профиль с текстурами — для sessionserver (profile / hasJoined)."""
    payload = _profile(account)
    payload["properties"] = []
    tex = _textures_property(account, request)
    if tex is not None:
        payload["properties"].append(tex)
    return payload


async def handle_authenticate(request):
    body = await _read_body(request)
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    client_token = str(body.get("clientToken") or "")
    account = db.get_account_by_nickname(username)
    if account is None or not db.verify_password(password, account["password_hash"]):
        return _error("Неверный никнейм или пароль.")
    if not client_token:
        client_token = None
    access_token = db.create_session(account["id"], client_token)
    if client_token is None:
        row = db.get_session(access_token)
        client_token = row["client_token"]
    return web.json_response(
        _auth_payload(account, access_token, client_token), headers=CORS_HEADERS
    )


async def handle_refresh(request):
    body = await _read_body(request)
    token = str(body.get("accessToken") or body.get("authToken") or "")
    session = db.get_session(token)
    if session is None:
        return _error("Недействительный токен авторизации.")
    given_client_token = str(body.get("clientToken") or "")
    if given_client_token and given_client_token != session["client_token"]:
        return _error("Неверный clientToken.")
    new_token = db.rotate_session(token)
    if new_token is None:
        return _error("Недействительный токен авторизации.")
    account = db.get_account_by_uuid(session["uuid"])
    if account is None:
        return _error("Аккаунт не найден.")
    return web.json_response(
        _auth_payload(account, new_token, session["client_token"]),
        headers=CORS_HEADERS,
    )


async def handle_validate(request):
    body = await _read_body(request)
    token = str(body.get("accessToken") or "")
    session = db.get_session(token)
    if session is None:
        return _error("Недействительный токен авторизации.")
    return _cors_response(204)


async def handle_signout(request):
    body = await _read_body(request)
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    account = db.get_account_by_nickname(username)
    if account is None or not db.verify_password(password, account["password_hash"]):
        return _error("Неверный никнейм или пароль.")
    db.delete_sessions_for_account(account["id"])
    return _cors_response(204)


async def handle_invalidate(request):
    body = await _read_body(request)
    token = str(body.get("accessToken") or "")
    db.delete_session(token)
    return _cors_response(204)


async def handle_metadata(request):
    public_url = config.get("public_url").rstrip("/")
    payload = {
        "meta": {
            "serverName": "Polit Land",
            "implementationName": "Polit Land Auth",
            "implementationVersion": "1.0.0",
            "feature.non_email_login": True,
            "feature.authserver": True,
            "feature.yggdrasil": True,
            "feature.legacy_skin_api": False,
            "feature.telemetry": False,
            "links": {},
        },
        "skinDomains": [_public_host()],
        "signaturePublickey": public_key_pem(),
        "meta.urls": {
            "authserver": public_url,
            "sessionServer": public_url,
            "skins": public_url,
        },
    }
    return web.json_response(payload, headers=CORS_HEADERS)


async def handle_profile(request):
    uuid_with_dashes = request.match_info.get("uuid", "")
    norm = uuid_with_dashes.replace("-", "").lower()
    account = db.get_account_by_uuid(norm)
    if account is None:
        return web.Response(status=204, headers=CORS_HEADERS)
    return web.json_response(_full_profile(account, request), headers=CORS_HEADERS)


async def handle_join(request):
    body = await _read_body(request)
    token = str(body.get("accessToken") or "")
    profile_uuid = str(body.get("selectedProfile") or "").replace("-", "").lower()
    server_id = str(body.get("serverId") or "")
    session = db.get_session(token)
    if session is None:
        return _error("Недействительный токен авторизации.")
    account = db.get_account_by_uuid(profile_uuid)
    if account is None:
        return _error("Профиль не найден.")
    if account["uuid"].replace("-", "").lower() != profile_uuid:
        return _error("Неверный профиль.")
    join_sessions[server_id] = {
        "name": account["nickname"],
        "uuid": profile_uuid,
        "expires": time.time() + 30,
    }
    return _cors_response(204)


async def handle_has_joined(request):
    username = str(request.query.get("username") or "")
    server_id = str(request.query.get("serverId") or "")
    rec = join_sessions.get(server_id)
    if rec is None or rec["expires"] < time.time() or rec["name"] != username:
        return _cors_response(204)
    account = db.get_account_by_nickname(username)
    if account is None:
        return _cors_response(204)
    return web.json_response(_full_profile(account, request), headers=CORS_HEADERS)


async def handle_profiles_minecraft(request):
    body = await _read_body(request)
    names = body if isinstance(body, list) else [body]
    profiles = []
    for name in names:
        account = db.get_account_by_nickname(str(name))
        if account is not None:
            profiles.append(_profile(account))
    return web.json_response(profiles, headers=CORS_HEADERS)


# ---------------------------------------------------------------- скины ------


def _account_from_token(body):
    token = str(body.get("accessToken") or "")
    session = db.get_session(token)
    if session is None:
        return None
    return db.get_account_by_uuid(session["uuid"])


async def handle_skin_upload(request):
    """Загрузка скина. Авторизация — по accessToken игрока.

    Тело: JSON {accessToken, model, png} где png — base64 PNG.
    """
    body = await _read_body(request)
    account = _account_from_token(body)
    if account is None:
        return _error("Недействительный токен авторизации.")
    raw_b64 = str(body.get("png") or "")
    if not raw_b64:
        return _error("Файл скина не передан.")
    try:
        png = base64.b64decode(raw_b64, validate=True)
    except Exception:
        return _error("Файл скина повреждён (не base64).")
    if len(png) > MAX_SKIN_BYTES:
        return _error(f"Файл слишком большой (максимум {MAX_SKIN_BYTES // 1024} КБ).")
    dims = _png_dimensions(png)
    if dims is None:
        return _error("Это не PNG-файл.")
    if dims not in ALLOWED_SKIN_SIZES:
        allowed = ", ".join(f"{w}x{h}" for w, h in ALLOWED_SKIN_SIZES)
        return _error(f"Размер {dims[0]}x{dims[1]} не поддерживается. Нужно: {allowed}.")
    model = str(body.get("model") or "default")
    skin_hash = db.set_skin(account["id"], png, model)
    log.info("skin updated: %s -> %s (%s)", account["nickname"], skin_hash, model)
    base = config.get("public_url").rstrip("/")
    return web.json_response(
        {"ok": True, "hash": skin_hash, "model": model, "url": f"{base}/textures/{skin_hash}"},
        headers=CORS_HEADERS,
    )


async def handle_skin_delete(request):
    body = await _read_body(request)
    account = _account_from_token(body)
    if account is None:
        return _error("Недействительный токен авторизации.")
    removed = db.delete_skin(account["id"])
    return web.json_response({"ok": True, "removed": removed}, headers=CORS_HEADERS)


async def handle_skin_info(request):
    """Информация о скине по нику — публично, для превью в лаунчере."""
    nickname = str(request.query.get("username") or "").strip()
    account = db.get_account_by_nickname(nickname)
    if account is None:
        return web.json_response({"ok": False, "error": "no_account"}, headers=CORS_HEADERS)
    skin = db.get_skin(account["id"])
    base = config.get("public_url").rstrip("/")
    if skin is None:
        return web.json_response({"ok": True, "hasSkin": False}, headers=CORS_HEADERS)
    return web.json_response(
        {
            "ok": True,
            "hasSkin": True,
            "hash": skin["hash"],
            "model": skin["model"],
            "updatedAt": skin["updated_at"],
            "url": f"{base}/textures/{skin['hash']}",
        },
        headers=CORS_HEADERS,
    )


async def handle_texture(request):
    skin_hash = str(request.match_info.get("hash", ""))
    if not skin_hash.isalnum() or len(skin_hash) > 64:
        return web.Response(status=404, headers=CORS_HEADERS)
    full = db.skin_file(skin_hash)
    if not os.path.isfile(full):
        return web.Response(status=404, headers=CORS_HEADERS)
    headers = dict(CORS_HEADERS)
    headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return web.FileResponse(full, headers=headers)


# ---------------------------------------------------------------- моды -------


async def handle_mods_manifest(request):
    return web.json_response(mods.get_manifest(), headers=CORS_HEADERS)


async def handle_mod_download(request):
    name = str(request.match_info.get("name", ""))
    full = mods.mod_path(name)
    if full is None:
        return web.Response(status=404, headers=CORS_HEADERS)
    return web.FileResponse(full, headers=dict(CORS_HEADERS))


# --------------------------------------------------- сборка клиента ----------


async def handle_pack_manifest(request):
    """Полный состав сборки: моды, конфиги, ресурспаки и прочее."""
    return web.json_response(pack.get_manifest(), headers=CORS_HEADERS)


async def handle_pack_download(request):
    group = str(request.match_info.get("group", ""))
    rel = str(request.match_info.get("path", ""))
    full = pack.file_path(group, rel)
    if full is None:
        return web.Response(status=404, headers=CORS_HEADERS)
    return web.FileResponse(full, headers=dict(CORS_HEADERS))


# ------------------------------------------------- обновления лаунчера -------


LAUNCHER_ASAR = os.path.join(config.BASE_DIR, "updates", "app.asar")
LAUNCHER_VERSION_INFO = os.path.join(config.BASE_DIR, "updates", "version.json")
CLEAN_ASAR = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local")),
    "Programs", "FrogLauncher", "resources", "app.asar.bak",
)
PATCHES_DIR = os.path.join(config.BASE_DIR, "patches")
REBUILD_SCRIPT = os.path.join(config.BASE_DIR, "rebuild_asar.py")
_asar_hash_cache = {"mtime": None, "sha256": None}


def _launcher_version_name(sha256):
    """Название версии из updates/version.json; показывается только если
    оно относится к текущей опубликованной сборке."""
    try:
        with open(LAUNCHER_VERSION_INFO, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if data.get("sha256") == sha256:
            return str(data.get("name", ""))[:200]
    except Exception:
        pass
    return None


def _launcher_asar_info():
    """sha256 считается один раз на версию файла (кэш по mtime)."""
    if not os.path.isfile(LAUNCHER_ASAR):
        return None
    st = os.stat(LAUNCHER_ASAR)
    if _asar_hash_cache["mtime"] != st.st_mtime:
        h = hashlib.sha256()
        with open(LAUNCHER_ASAR, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        _asar_hash_cache["mtime"] = st.st_mtime
        _asar_hash_cache["sha256"] = h.hexdigest()
    return {"available": True, "sha256": _asar_hash_cache["sha256"], "size": st.st_size}


async def handle_launcher_version(request):
    info = _launcher_asar_info()
    if not info:
        return web.json_response({"ok": True, "available": False}, headers=CORS_HEADERS)
    name = _launcher_version_name(info["sha256"])
    return web.json_response(
        {"ok": True, **info, "name": name}, headers=CORS_HEADERS
    )


async def handle_launcher_download(request):
    if not os.path.isfile(LAUNCHER_ASAR):
        return web.Response(status=404, headers=CORS_HEADERS)
    return web.FileResponse(LAUNCHER_ASAR, headers=dict(CORS_HEADERS))


# ------------------------------------------------- админ-панель --------------
#  Страница /admin: загрузка модов в mods_repo и новой сборки лаунчера
#  (updates/app.asar). Доступ по паролю из config.json -> "admin_password".

import secrets  # noqa: E402

ADMIN_SESSION_TTL = 12 * 3600
_admin_tokens = {}  # token -> expires_at


def _check_admin(request):
    tok = request.headers.get("X-Admin-Token", "")
    exp = _admin_tokens.get(tok)
    if not tok or not exp or exp < time.time():
        return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
    _admin_tokens[tok] = time.time() + ADMIN_SESSION_TTL  # скользящее окно
    return None


async def handle_admin_page(request):
    page = os.path.join(config.BASE_DIR, "admin.html")
    if not os.path.isfile(page):
        return web.Response(status=404, text="admin.html не найден рядом с server.py")
    return web.FileResponse(page)


async def handle_admin_login(request):
    body = await _read_body(request)
    password = str(body.get("password", ""))
    expected = config.get("admin_password")
    if not expected:
        return web.json_response(
            {"ok": False, "error": "В config.json не задан admin_password"}, status=500
        )
    if not secrets.compare_digest(password, str(expected)):
        return web.json_response({"ok": False, "error": "Неверный пароль"}, status=401)
    token = secrets.token_urlsafe(32)
    _admin_tokens[token] = time.time() + ADMIN_SESSION_TTL
    return web.json_response({"ok": True, "token": token})


async def handle_admin_state(request):
    deny = _check_admin(request)
    if deny:
        return deny
    mods_list = []
    manifest = mods.get_manifest()
    repo = mods.repo_dir()
    for item in manifest["mods"]:
        try:
            mtime = int(os.stat(os.path.join(repo, item["name"])).st_mtime)
        except OSError:
            mtime = 0
        mods_list.append({"name": item["name"], "size": item["size"], "mtime": mtime})
    launcher = None
    info = _launcher_asar_info()
    if info:
        launcher = {
            "sha256": info["sha256"],
            "size": info["size"],
            "mtime": int(os.stat(LAUNCHER_ASAR).st_mtime),
            "name": _launcher_version_name(info["sha256"]),
        }
    pack_manifest = pack.get_manifest()
    pack_groups = []
    for g in pack.GROUPS:
        found = next((x for x in pack_manifest["groups"] if x["name"] == g["name"]), None)
        files = []
        if found:
            root = pack.group_dir(g["name"])
            for item in found["files"]:
                try:
                    mtime = int(os.stat(os.path.join(root, *item["path"].split("/"))).st_mtime)
                except OSError:
                    mtime = 0
                files.append({"path": item["path"], "size": item["size"], "mtime": mtime})
        pack_groups.append(
            {
                "name": g["name"],
                "target": g["target"],
                "mode": g["mode"],
                "only": list(g["only"]) if g["only"] else None,
                "count": len(files),
                "files": files,
            }
        )
    return web.json_response(
        {
            "ok": True,
            "mods_count": len(mods_list),
            "mods": mods_list,
            "launcher": launcher,
            "backup": os.path.isfile(LAUNCHER_ASAR + ".bak"),
            "clients_expected": manifest["count"],
            "pack_revision": pack_manifest["revision"],
            "pack": pack_groups,
            "server": await asyncio.get_event_loop().run_in_executor(
                None, lambda: mcserver.snapshot({m["name"] for m in mods_list})
            ),
        },
        headers=CORS_HEADERS,
    )


def _safe_jar_name(name):
    name = os.path.basename(name or "")
    if not name.lower().endswith(".jar"):
        return None
    clean = "".join(c for c in name if c.isalnum() or c in "._-+ ()[]")
    if not clean or clean.startswith("."):
        return None
    return clean


async def handle_admin_mods_upload(request):
    deny = _check_admin(request)
    if deny:
        return deny
    reader = await request.multipart()
    saved, errors = [], []
    while True:
        part = await reader.next()
        if part is None:
            break
        if (part.name or "") != "files":
            continue
        name = _safe_jar_name(part.filename)
        if not name:
            errors.append({"file": part.filename, "error": "нужно .jar"})
            continue
        dest = os.path.join(mods.repo_dir(), name)
        tmp = dest + ".part"
        try:
            with open(tmp, "wb") as f:
                while True:
                    chunk = await part.read_chunk(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
            os.replace(tmp, dest)
            saved.append(name)
        except Exception as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            errors.append({"file": name, "error": str(e)})
    mods.invalidate()
    pack.invalidate()
    log.info("Admin: загружено модов %d (%s)", len(saved), ", ".join(saved) or "-")
    return web.json_response({"ok": True, "saved": saved, "errors": errors}, headers=CORS_HEADERS)


async def handle_admin_mod_delete(request):
    deny = _check_admin(request)
    if deny:
        return deny
    body = await _read_body(request)
    full = mods.mod_path(str(body.get("name", "")))
    if full is None:
        return web.json_response({"ok": False, "error": "мод не найден"}, status=404)
    os.remove(full)
    mods.invalidate()
    pack.invalidate()
    log.info("Admin: удалён мод %s", os.path.basename(full))
    return web.json_response({"ok": True}, headers=CORS_HEADERS)


def _safe_rel_path(raw):
    """Относительный путь внутри группы: без обхода наверх и без имён с диском."""
    rel = str(raw or "").replace("\\", "/").strip("/")
    if not rel:
        return None
    parts = []
    for p in rel.split("/"):
        p = p.strip()
        if not p or p == "." or p == ".." or p.startswith("."):
            return None
        if ":" in p or any(ch in p for ch in '<>:"|?*'):
            return None
        parts.append(p)
    if len(parts) > 12:
        return None
    return "/".join(parts)


async def handle_admin_pack_upload(request):
    """Загрузка файлов сборки: поле group + files с относительными путями."""
    deny = _check_admin(request)
    if deny:
        return deny
    reader = await request.multipart()
    group = ""
    saved, errors = [], []
    while True:
        part = await reader.next()
        if part is None:
            break
        field = part.name or ""
        if field == "group":
            group = (await part.text()).strip()
            continue
        if field != "files":
            continue
        if group not in pack.GROUP_BY_NAME:
            errors.append({"file": part.filename, "error": "неизвестная группа"})
            await part.read()
            continue
        # имя файла может прийти с путём (webkitdirectory отдаёт a/b/c.json)
        rel = _safe_rel_path(part.filename)
        if not rel:
            errors.append({"file": part.filename, "error": "недопустимое имя"})
            await part.read()
            continue
        gcfg = pack.GROUP_BY_NAME[group]
        if gcfg["only"] and not rel.lower().endswith(tuple(gcfg["only"])):
            errors.append({"file": rel, "error": "в эту группу нужен " + ", ".join(gcfg["only"])})
            await part.read()
            continue
        dest = os.path.join(pack.group_dir(group), *rel.split("/"))
        tmp = dest + ".part"
        try:
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(tmp, "wb") as f:
                while True:
                    chunk = await part.read_chunk(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
            os.replace(tmp, dest)
            saved.append(rel)
        except Exception as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            errors.append({"file": rel, "error": str(e)})
    if group == "mods":
        mods.invalidate()
    pack.invalidate()
    log.info("Admin: в группу %s загружено %d файлов", group or "?", len(saved))
    return web.json_response({"ok": True, "group": group, "saved": saved, "errors": errors}, headers=CORS_HEADERS)


async def handle_admin_pack_delete(request):
    deny = _check_admin(request)
    if deny:
        return deny
    body = await _read_body(request)
    group = str(body.get("group", ""))
    full = pack.file_path(group, body.get("path", ""))
    if full is None:
        return web.json_response({"ok": False, "error": "файл не найден"}, status=404)
    os.remove(full)
    # подчищаем опустевшие подпапки, чтобы репозиторий не зарастал
    try:
        root = os.path.realpath(pack.group_dir(group))
        d = os.path.dirname(os.path.realpath(full))
        while d.startswith(root + os.sep) and not os.listdir(d):
            os.rmdir(d)
            d = os.path.dirname(d)
    except OSError:
        pass
    if group == "mods":
        mods.invalidate()
    pack.invalidate()
    log.info("Admin: удалён файл сборки %s/%s", group, body.get("path"))
    return web.json_response({"ok": True}, headers=CORS_HEADERS)


def _valid_asar(path):
    """Грубая проверка структуры asar: [4][header_size][obj_size][json_len]{JSON}."""
    try:
        with open(path, "rb") as f:
            head = f.read(16)
            if len(head) < 16 or head[0:4] != b"\x04\x00\x00\x00":
                return False
            json_len = struct.unpack("<I", head[12:16])[0]
            if not (2 <= json_len <= 64 * 1024 * 1024):
                return False
            js = f.read(json_len)
        obj = json.loads(js.decode("utf-8", "ignore"))
        return isinstance(obj, dict) and "files" in obj
    except Exception:
        return False


def _publish_asar(tmp, label):
    """Публикует собранный/загруженный asar: бэкап + устойчивая замена."""
    os.makedirs(os.path.dirname(LAUNCHER_ASAR), exist_ok=True)
    if os.path.isfile(LAUNCHER_ASAR):
        shutil.copy2(LAUNCHER_ASAR, LAUNCHER_ASAR + ".bak")
    try:
        os.replace(tmp, LAUNCHER_ASAR)
    except PermissionError:
        # файл может быть открыт другими процессами без права delete —
        # тогда просто перезаписываем содержимое
        with open(tmp, "rb") as src_f, open(LAUNCHER_ASAR, "wb") as dst_f:
            shutil.copyfileobj(src_f, dst_f)
        os.remove(tmp)
    _asar_hash_cache["mtime"] = None
    info = _launcher_asar_info()
    try:
        with open(LAUNCHER_VERSION_INFO, "w", encoding="utf-8") as f:
            json.dump({"sha256": info["sha256"], "name": label, "published": int(time.time())}, f, ensure_ascii=False, indent=2)
    except OSError:
        pass
    log.info("Admin: опубликована сборка лаунчера %s (%s)", info["sha256"][:10], label or "без названия")
    return {"ok": True, **info, "name": label or None}


# ------------------------------------------- локальный Minecraft-сервер -----


def _mc_disabled():
    return web.json_response(
        {"ok": False, "error": "Minecraft-сервер есть только на домашнем ПК (не задан mc_server_dir)"},
        status=400,
        headers=CORS_HEADERS,
    )


async def handle_admin_server_mods_upload(request):
    deny = _check_admin(request)
    if deny:
        return deny
    if not mcserver.enabled():
        return _mc_disabled()
    reader = await request.multipart()
    saved, errors = [], []
    while True:
        part = await reader.next()
        if part is None:
            break
        if (part.name or "") != "files":
            continue
        name = _safe_jar_name(part.filename or "")
        if not name:
            errors.append({"file": part.filename, "error": "нужно имя вида mod.jar"})
            await part.read()
            continue
        dest = os.path.join(mcserver.mods_dir(), name)
        tmp = dest + ".part"
        try:
            with open(tmp, "wb") as f:
                while True:
                    chunk = await part.read_chunk(1 << 20)
                    if not chunk:
                        break
                    f.write(chunk)
            os.replace(tmp, dest)
            saved.append(name)
        except PermissionError:
            try:
                os.remove(tmp)
            except OSError:
                pass
            # java держит jar открытым, пока сервер запущен — перезаписать нельзя
            errors.append(
                {"file": name, "error": "файл занят запущенным сервером — останови сервер и загрузи заново"}
            )
        except Exception as e:
            try:
                os.remove(tmp)
            except OSError:
                pass
            errors.append({"file": name, "error": str(e)})
    log.info("Admin: на сервер загружено модов %d (%s)", len(saved), ", ".join(saved) or "-")
    return web.json_response({"ok": True, "saved": saved, "errors": errors}, headers=CORS_HEADERS)


async def handle_admin_server_mod_delete(request):
    deny = _check_admin(request)
    if deny:
        return deny
    if not mcserver.enabled():
        return _mc_disabled()
    body = await _read_body(request)
    name = _safe_jar_name(str(body.get("name", "")))
    dest = os.path.join(mcserver.mods_dir(), name) if name else ""
    if not name or not os.path.isfile(dest):
        return web.json_response({"ok": False, "error": "мод не найден"}, status=404, headers=CORS_HEADERS)
    try:
        os.remove(dest)
    except OSError as e:
        return web.json_response({"ok": False, "error": str(e)}, status=500, headers=CORS_HEADERS)
    log.info("Admin: с сервера удалён мод %s", name)
    return web.json_response({"ok": True}, headers=CORS_HEADERS)


async def handle_admin_server_power(request):
    """start / stop / restart. Остановка — штатная через RCON `stop`."""
    deny = _check_admin(request)
    if deny:
        return deny
    if not mcserver.enabled():
        return _mc_disabled()
    body = await _read_body(request)
    action = str(body.get("action", ""))
    force = bool(body.get("force"))
    loop = asyncio.get_event_loop()

    if action == "stop":
        ok, msg = await loop.run_in_executor(None, lambda: mcserver.stop_server(force=force))
    elif action == "restart":
        ok, msg = await loop.run_in_executor(None, lambda: mcserver.restart_server(force=force))
    elif action == "start":
        ok, msg = mcserver.start_server()
    else:
        return web.json_response({"ok": False, "error": "неизвестное действие"}, status=400, headers=CORS_HEADERS)

    mcserver.invalidate_pid_cache()
    log.info("Admin: действие над MC-сервером %s -> %s (%s)", action, ok, msg)
    return web.json_response({"ok": ok, "message": msg}, headers=CORS_HEADERS)


async def handle_admin_launcher_upload(request):
    deny = _check_admin(request)
    if deny:
        return deny
    reader = await request.multipart()
    tmp = LAUNCHER_ASAR + ".part"
    label = ""
    got = False
    while True:
        part = await reader.next()
        if part is None:
            break
        if (part.name or "") == "name":
            label = (await part.text()).strip()[:200]
            continue
        if (part.name or "") != "file":
            continue
        with open(tmp, "wb") as f:
            while True:
                chunk = await part.read_chunk(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
        got = True
        break
    if not got or not os.path.isfile(tmp):
        return web.json_response({"ok": False, "error": "файл не получен"}, status=400)
    if not _valid_asar(tmp):
        os.remove(tmp)
        return web.json_response(
            {"ok": False, "error": "это не похоже на app.asar (битая структура)"}, status=400
        )
    result = _publish_asar(tmp, label)
    return web.json_response(result, headers=CORS_HEADERS)


async def handle_admin_launcher_rebuild(request):
    """Собирает лаунчер заново из чистой копии + patches/web и публикует."""
    deny = _check_admin(request)
    if deny:
        return deny
    body = await _read_body(request)
    label = str(body.get("name", "")).strip()[:200]
    if not os.path.isfile(CLEAN_ASAR):
        return web.json_response(
            {"ok": False, "error": "не найдена чистая копия app.asar.bak рядом с лаунчером"},
            status=400,
        )
    if not os.path.isdir(PATCHES_DIR):
        return web.json_response({"ok": False, "error": "нет папки patches/web"}, status=500)
    tmp = LAUNCHER_ASAR + ".build"
    shutil.copy2(CLEAN_ASAR, tmp)
    try:
        proc = await asyncio.create_subprocess_exec(
            sys.executable, REBUILD_SCRIPT, tmp, PATCHES_DIR,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=config.BASE_DIR,
        )
        out_bytes, _ = await proc.communicate()
        ok_build = proc.returncode == 0 and os.path.isfile(tmp) and _valid_asar(tmp)
        out_tail = (out_bytes or b"").decode("utf-8", "replace").strip()[-400:]
        if not ok_build:
            return web.json_response(
                {"ok": False, "error": "сборка не удалась: " + (out_tail or "неизвестная ошибка")},
                status=500,
            )
        result = _publish_asar(tmp, label)
        result["build_log"] = out_tail
        return web.json_response(result, headers=CORS_HEADERS)
    finally:
        if os.path.isfile(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


async def handle_admin_launcher_name(request):
    """Переименовать текущую опубликованную версию без перезагрузки файла."""
    deny = _check_admin(request)
    if deny:
        return deny
    body = await _read_body(request)
    name = str(body.get("name", "")).strip()[:200]
    info = _launcher_asar_info()
    if not info:
        return web.json_response({"ok": False, "error": "сборка не публиковалась"}, status=400)
    try:
        with open(LAUNCHER_VERSION_INFO, "w", encoding="utf-8") as f:
            json.dump({"sha256": info["sha256"], "name": name, "published": int(time.time())}, f, ensure_ascii=False, indent=2)
    except OSError:
        pass
    log.info("Admin: версия %s названа «%s»", info["sha256"][:10], name)
    return web.json_response({"ok": True, "name": name or None}, headers=CORS_HEADERS)


async def handle_admin_launcher_rollback(request):
    deny = _check_admin(request)
    if deny:
        return deny
    bak = LAUNCHER_ASAR + ".bak"
    if not os.path.isfile(bak):
        return web.json_response({"ok": False, "error": "резервной копии нет"}, status=400)
    shutil.copy2(bak, LAUNCHER_ASAR)
    _asar_hash_cache["mtime"] = None
    info = _launcher_asar_info()
    log.info("Admin: откат сборки лаунчера на %s", info["sha256"][:10])
    return web.json_response({"ok": True, **info}, headers=CORS_HEADERS)


async def handle_root(request):
    return web.json_response(
        {
            "name": "Polit Land Auth",
            "endpoints": [
                "POST /auth/authenticate",
                "POST /auth/refresh",
                "POST /auth/validate",
                "POST /auth/signout",
                "POST /auth/invalidate",
                "GET /api/authlib-injector",
                "GET /sessionserver/session/minecraft/profile/{uuid}",
                "POST /api/skin/upload",
                "POST /api/skin/delete",
                "GET /api/skin/info?username=",
                "GET /textures/{hash}",
                "GET /api/mods/manifest",
                "GET /api/mods/file/{name}",
                "GET /api/launcher/version",
                "GET /api/launcher/download",
                "GET /admin (панель управления)",
            ],
        },
        headers=CORS_HEADERS,
    )


async def on_startup(app):
    db.init_db()
    config.write_launcher_auth_config()
    log.info(
        "Auth server ready at http://%s:%s (public: %s)",
        config.get("host"),
        config.get("port"),
        config.get("public_url"),
    )


def build_app():
    # большой client_max_size: через панель грузятся jar-моды и app.asar (~100+ МБ)
    app = web.Application(middlewares=[cors_middleware], client_max_size=2 * 1024**3)
    app.on_startup.append(on_startup)
    # Лаунчер (прямые пути)
    app.router.add_post("/auth/authenticate", handle_authenticate)
    app.router.add_post("/auth/refresh", handle_refresh)
    app.router.add_post("/auth/validate", handle_validate)
    app.router.add_post("/auth/signout", handle_signout)
    app.router.add_post("/auth/invalidate", handle_invalidate)
    # Метаданные для authlib-injector
    app.router.add_get("/api/authlib-injector", handle_metadata)
    # Пути authlib-injector (apiRoot = .../api/authlib-injector/)
    app.router.add_post("/api/authlib-injector/authserver/authenticate", handle_authenticate)
    app.router.add_post("/api/authlib-injector/authserver/refresh", handle_refresh)
    app.router.add_post("/api/authlib-injector/authserver/validate", handle_validate)
    app.router.add_post("/api/authlib-injector/authserver/signout", handle_signout)
    app.router.add_post("/api/authlib-injector/authserver/invalidate", handle_invalidate)
    app.router.add_post("/api/authlib-injector/sessionserver/session/minecraft/join", handle_join)
    app.router.add_get(
        "/api/authlib-injector/sessionserver/session/minecraft/hasJoined", handle_has_joined
    )
    app.router.add_get(
        "/api/authlib-injector/sessionserver/session/minecraft/profile/{uuid}", handle_profile
    )
    app.router.add_post("/api/authlib-injector/api/profiles/minecraft", handle_profiles_minecraft)
    # Дополнительно: прямые пути сессии (если сервер использует их напрямую)
    app.router.add_post("/sessionserver/session/minecraft/join", handle_join)
    app.router.add_get("/sessionserver/session/minecraft/hasJoined", handle_has_joined)
    app.router.add_post("/api/profiles/minecraft", handle_profiles_minecraft)
    app.router.add_get(
        "/sessionserver/session/minecraft/profile/{uuid}", handle_profile
    )
    # Скины
    app.router.add_post("/api/skin/upload", handle_skin_upload)
    app.router.add_post("/api/skin/delete", handle_skin_delete)
    app.router.add_get("/api/skin/info", handle_skin_info)
    app.router.add_get("/textures/{hash}", handle_texture)
    # Каноничный набор модов
    app.router.add_get("/api/mods/manifest", handle_mods_manifest)
    app.router.add_get("/api/mods/file/{name}", handle_mod_download)
    app.router.add_get("/api/pack/manifest", handle_pack_manifest)
    app.router.add_get("/api/pack/file/{group}/{path:.+}", handle_pack_download)
    # Обновления лаунчера
    app.router.add_get("/api/launcher/version", handle_launcher_version)
    app.router.add_get("/api/launcher/download", handle_launcher_download)
    # Админ-панель
    app.router.add_get("/admin", handle_admin_page)
    app.router.add_post("/api/admin/login", handle_admin_login)
    app.router.add_get("/api/admin/state", handle_admin_state)
    app.router.add_post("/api/admin/mods/upload", handle_admin_mods_upload)
    app.router.add_post("/api/admin/mods/delete", handle_admin_mod_delete)
    app.router.add_post("/api/admin/pack/upload", handle_admin_pack_upload)
    app.router.add_post("/api/admin/pack/delete", handle_admin_pack_delete)
    app.router.add_post("/api/admin/server/mods/upload", handle_admin_server_mods_upload)
    app.router.add_post("/api/admin/server/mods/delete", handle_admin_server_mod_delete)
    app.router.add_post("/api/admin/server/power", handle_admin_server_power)
    app.router.add_post("/api/admin/launcher/upload", handle_admin_launcher_upload)
    app.router.add_post("/api/admin/launcher/rebuild", handle_admin_launcher_rebuild)
    app.router.add_post("/api/admin/launcher/name", handle_admin_launcher_name)
    app.router.add_post("/api/admin/launcher/rollback", handle_admin_launcher_rollback)
    app.router.add_get("/", handle_root)
    return app


@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        return _cors_response(204)
    response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


def main():
    db.init_db()
    config.write_launcher_auth_config()
    app = build_app()
    web.run_app(app, host=config.get("host"), port=config.get("port"), print=None)


if __name__ == "__main__":
    main()