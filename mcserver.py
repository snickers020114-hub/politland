"""Управление локальным Minecraft-сервером из админ-панели.

Панель умеет смотреть список модов сервера (minecraft-server\\mods),
добавлять и убирать их, а также запускать/останавливать сам сервер.

Моды сервера — отдельная сущность, не путать с клиентскими (mods_repo):
контентные моды должны стоять с обеих сторон и совпадать по версии,
иначе игрок не сможет зайти. Чисто серверные (права, экономика) и чисто
клиентские (шейдеры, миникарты) моды дублировать не нужно.

Запуск/остановка:
    старт   — start.bat в новом консольном окне (как руками);
    стоп    — штатно через RCON-команду `stop` (мир сохраняется);
              без RCON — только по force=true, через taskkill /F
              (риск повреждения мира, поэтому не по умолчанию).

На хостинге (Render) папки minecraft-server нет — все функции честно
сообщают, что управление недоступно, а панель просто прячет раздел.
"""

import os
import socket
import struct
import subprocess
import threading
import time

import config

_JVM_MARKER = "win_args.txt"  # только серверный java запущен с этим файлом

_pid_cache = None  # (timestamp, [pid])
_pid_lock = threading.Lock()


def enabled():
    """Есть ли вообще управляемый сервер на этой машине."""
    return bool(config.get("mc_server_dir")) and os.path.isdir(mc_dir())


def mc_dir():
    return config.get("mc_server_dir")


def mods_dir():
    return os.path.join(mc_dir(), "mods")


def read_properties():
    props = {}
    p = os.path.join(mc_dir(), "server.properties")
    try:
        with open(p, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                props[k.strip()] = v.strip().replace("\\:", ":")
    except OSError:
        pass
    return props


def list_mods():
    root = mods_dir()
    out = []
    if not os.path.isdir(root):
        return out
    for fn in sorted(os.listdir(root)):
        if not fn.lower().endswith(".jar"):
            continue
        full = os.path.join(root, fn)
        try:
            st = os.stat(full)
            out.append({"name": fn, "size": st.st_size, "mtime": int(st.st_mtime)})
        except OSError:
            continue
    return out


def java_pids(max_age=8.0):
    """PID всех java-процессов, запущенных как NeoForge-сервер (с кэшем)."""
    global _pid_cache
    with _pid_lock:
        now = time.time()
        if _pid_cache is not None and now - _pid_cache[0] < max_age:
            return list(_pid_cache[1])
        pids = []
        try:
            out = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-CimInstance Win32_Process -Filter \"name='java.exe'\" "
                    "| Where-Object { $_.CommandLine -match '%s' } "
                    "| ForEach-Object { $_.ProcessId }" % _JVM_MARKER,
                ],
                capture_output=True, text=True, timeout=30,
            )
            for token in out.stdout.split():
                if token.strip().isdigit():
                    pids.append(int(token))
        except Exception:
            pass
        _pid_cache = (now, list(pids))
        return pids


def invalidate_pid_cache():
    global _pid_cache
    with _pid_lock:
        _pid_cache = None


# ------------------------------------------------------------ RCON ----------


def _rcon_packet(req_id, ptype, payload):
    data = struct.pack("<ii", req_id, ptype) + payload.encode("utf-8") + b"\x00\x00"
    return struct.pack("<i", len(data)) + data


def _rcon_read(sock):
    def exact(n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("RCON connection closed")
            buf += chunk
        return buf

    (length,) = struct.unpack("<i", exact(4))
    data = exact(length)
    req_id, ptype = struct.unpack("<ii", data[:8])
    return req_id, ptype, data[8:-2]


def rcon_command(cmd):
    """Выполняет команду в консоли сервера. Возвращает (ok, текст)."""
    props = read_properties()
    if props.get("enable-rcon", "false").lower() != "true":
        return False, "RCON отключён в server.properties"
    host = props.get("rcon.ip", "127.0.0.1")
    port = int(props.get("rcon.port", "25575"))
    password = props.get("rcon.password", "")
    if not password:
        return False, "В server.properties не задан rcon.password"
    try:
        with socket.create_connection((host, port), timeout=6) as s:
            s.settimeout(10)
            s.sendall(_rcon_packet(1, 3, password))
            req_id, _, _ = _rcon_read(s)
            if req_id == -1:
                return False, "Неверный rcon.password"
            s.sendall(_rcon_packet(2, 2, cmd))
            _, _, payload = _rcon_read(s)
            return True, payload.decode("utf-8", "replace").strip()
    except OSError as e:
        return False, "Нет связи с RCON (%s): %s" % (props.get("rcon.port"), e)


# ------------------------------------------------------- запуск / стоп ------


def start_server():
    bat = os.path.join(mc_dir(), "start.bat")
    if not os.path.isfile(bat):
        return False, "start.bat не найден в " + mc_dir()
    if java_pids():
        return True, "Сервер уже запущен"
    try:
        subprocess.Popen(
            ["cmd", "/c", "start", "PolitLand MC", bat],
            cwd=mc_dir(),
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            close_fds=True,
        )
    except OSError as e:
        return False, "Не удалось запустить: %s" % e
    invalidate_pid_cache()
    return True, "Запускается — окно сервера откроется отдельно"


def stop_server(force=False, timeout=75):
    pids = java_pids()
    if not pids:
        return True, "Сервер и так не запущен"
    ok, msg = rcon_command("stop")
    if ok:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not java_pids(max_age=2.0):
                return True, "Сервер остановлен штатно (мир сохранён)"
            time.sleep(1.5)
        msg = "Сервер не ответил на stop за %d с" % timeout
    if not force:
        return False, msg + ". Можно остановить принудительно (force) — но это риск для мира."
    for pid in java_pids(max_age=2.0):
        try:
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True, timeout=20)
        except Exception:
            pass
    deadline = time.time() + 15
    while time.time() < deadline and java_pids(max_age=2.0):
        time.sleep(1)
    return True, "Остановлен принудительно (taskkill)"


def restart_server(force=False):
    if java_pids():
        ok, msg = stop_server(force=force)
        if not ok:
            return False, msg
        time.sleep(2)
    return start_server()


def snapshot(client_names):
    """Данные для карточки панели: статус + моды + кого не хватает на сервере."""
    if not enabled():
        return {"enabled": False}
    server_names = {m["name"] for m in list_mods()}
    return {
        "enabled": True,
        "running": bool(java_pids()),
        "port": read_properties().get("server-port", "25565"),
        "online_mode": read_properties().get("online-mode", "?") == "true",
        "mods": list_mods(),
        "clients_count": len(client_names),
        "missing_on_server": sorted(n for n in client_names if n not in server_names),
    }
