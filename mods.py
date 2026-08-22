"""Каноничный набор модов: манифест и раздача файлов.

Моды лежат в `mods_repo/` рядом с server.py. Манифест (имя + sha1 + размер)
считается один раз и пересчитывается только если папка изменилась.

Если папка отсутствует или пуста, манифест возвращается с `strict: false` —
лаунчер в этом случае ничего не трогает. Это безопасное состояние по умолчанию,
пока моды на сервер не загружены.
"""

import hashlib
import os
import threading

import config

REPO_DIRNAME = "mods_repo"
_lock = threading.Lock()
_cache = None  # (signature, manifest)


def repo_dir():
    return os.path.join(config.BASE_DIR, REPO_DIRNAME)


def _is_mod(name):
    return name.lower().endswith(".jar")


def _dir_signature(path):
    """Дешёвая подпись состояния папки: имя+размер+mtime каждого jar."""
    if not os.path.isdir(path):
        return None
    parts = []
    for name in sorted(os.listdir(path)):
        if not _is_mod(name):
            continue
        full = os.path.join(path, name)
        try:
            st = os.stat(full)
        except OSError:
            continue
        parts.append(f"{name}:{st.st_size}:{int(st.st_mtime)}")
    return "|".join(parts)


def _sha1_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _build_manifest(path, signature):
    mods = []
    for name in sorted(os.listdir(path)):
        if not _is_mod(name):
            continue
        full = os.path.join(path, name)
        try:
            mods.append(
                {
                    "name": name,
                    "size": os.path.getsize(full),
                    "sha1": _sha1_file(full),
                }
            )
        except OSError:
            continue
    return {
        "strict": len(mods) > 0,
        "count": len(mods),
        "revision": hashlib.sha1((signature or "").encode("utf-8")).hexdigest()[:16],
        "mods": mods,
    }


def get_manifest():
    path = repo_dir()
    signature = _dir_signature(path)
    if signature is None or signature == "":
        return {"strict": False, "count": 0, "revision": "empty", "mods": []}
    with _lock:
        global _cache
        if _cache is not None and _cache[0] == signature:
            return _cache[1]
        manifest = _build_manifest(path, signature)
        _cache = (signature, manifest)
        return manifest


def mod_path(name):
    """Безопасно разрешает имя мода в путь внутри mods_repo."""
    if not name or not _is_mod(name):
        return None
    if os.path.basename(name) != name:
        return None
    if name.startswith("."):
        return None
    full = os.path.join(repo_dir(), name)
    if not os.path.isfile(full):
        return None
    # защита от симлинков наружу
    real_repo = os.path.realpath(repo_dir())
    if not os.path.realpath(full).startswith(real_repo + os.sep):
        return None
    return full


def invalidate():
    with _lock:
        global _cache
        _cache = None
