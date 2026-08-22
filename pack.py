"""Каноничная сборка клиента: манифест и раздача любых файлов, не только модов.

Раньше синхронизировались только `mods/`. Теперь сервер описывает несколько
групп файлов, каждая со своей политикой обновления:

    strict — папка приводится к серверному состоянию один в один:
             лишние файлы уносятся в карантин, изменённые перекачиваются.
             Так ведут себя моды: набор должен совпадать у всех, иначе
             игрока выкинет с сервера.

    sync   — сервер досылает свои файлы (новые и изменённые), но чужие не
             трогает. Для ресурспаков и шейдеров: свои игрок добавлять может.

    seed   — файл ставится, если его нет. Если на сервере он изменился, он
             перезапишется только когда игрок сам его не правил (сверяем с
             тем, что синхронизировали в прошлый раз). Так обновляются
             конфиги: настройки игрока (управление, громкость) не сбрасываются.

Источники:
    mods          -> mods_repo/         (уже существующая папка, не переезжает)
    остальное     -> pack_repo/<группа>/...

Пустая группа просто отсутствует в манифесте, и лаунчер её пропускает.
"""

import hashlib
import os
import threading

import config

MODS_DIRNAME = "mods_repo"
PACK_DIRNAME = "pack_repo"

# Порядок важен: моды первыми, они критичны для входа на сервер.
GROUPS = (
    {"name": "mods", "target": "mods", "mode": "strict", "only": (".jar",)},
    {"name": "config", "target": "config", "mode": "seed", "only": None},
    {"name": "defaultconfigs", "target": "defaultconfigs", "mode": "seed", "only": None},
    {"name": "resourcepacks", "target": "resourcepacks", "mode": "sync", "only": None},
    {"name": "shaderpacks", "target": "shaderpacks", "mode": "sync", "only": None},
    {"name": "kubejs", "target": "kubejs", "mode": "sync", "only": None},
)
GROUP_BY_NAME = {g["name"]: g for g in GROUPS}

_lock = threading.Lock()
_cache = None  # (signature, manifest)


def mods_dir():
    return os.path.join(config.BASE_DIR, MODS_DIRNAME)


def pack_dir():
    return os.path.join(config.BASE_DIR, PACK_DIRNAME)


def group_dir(name):
    """Папка-источник группы. Моды остаются в mods_repo для совместимости."""
    if name == "mods":
        return mods_dir()
    return os.path.join(pack_dir(), name)


def _allowed(name, only):
    if only is None:
        return not name.startswith(".")
    return name.lower().endswith(tuple(only))


def _walk_group(root, only):
    """Отдаёт (относительный путь с '/', полный путь) по всем файлам группы."""
    if not os.path.isdir(root):
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for fn in sorted(filenames):
            if not _allowed(fn, only):
                continue
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            yield rel, full


def _group_signature(name, only):
    root = group_dir(name)
    parts = []
    for rel, full in _walk_group(root, only):
        try:
            st = os.stat(full)
        except OSError:
            continue
        parts.append(f"{rel}:{st.st_size}:{int(st.st_mtime)}")
    return "|".join(parts)


def _signature():
    return "||".join(g["name"] + "=" + _group_signature(g["name"], g["only"]) for g in GROUPS)


def _sha1_file(path):
    h = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _build(signature):
    groups = []
    for g in GROUPS:
        root = group_dir(g["name"])
        files = []
        for rel, full in _walk_group(root, g["only"]):
            try:
                files.append({"path": rel, "size": os.path.getsize(full), "sha1": _sha1_file(full)})
            except OSError:
                continue
        if not files:
            continue
        groups.append(
            {
                "name": g["name"],
                "target": g["target"],
                "mode": g["mode"],
                "count": len(files),
                "files": files,
            }
        )
    return {
        "revision": hashlib.sha1(signature.encode("utf-8")).hexdigest()[:16],
        "groups": groups,
    }


def get_manifest():
    signature = _signature()
    with _lock:
        global _cache
        if _cache is not None and _cache[0] == signature:
            return _cache[1]
        manifest = _build(signature)
        _cache = (signature, manifest)
        return manifest


def file_path(group, rel):
    """Безопасно разрешает (группа, относительный путь) в файл внутри группы."""
    g = GROUP_BY_NAME.get(str(group))
    if g is None:
        return None
    rel = str(rel or "").replace("\\", "/").strip("/")
    if not rel or ".." in rel.split("/"):
        return None
    if not _allowed(os.path.basename(rel), g["only"]):
        return None
    root = os.path.realpath(group_dir(g["name"]))
    full = os.path.realpath(os.path.join(root, rel))
    if full != root and not full.startswith(root + os.sep):
        return None
    if not os.path.isfile(full):
        return None
    return full


def invalidate():
    with _lock:
        global _cache
        _cache = None
