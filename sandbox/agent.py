#!/usr/bin/env python3
"""Sentinel sandbox supervisor - runs *inside* the shadow container (standard library only).

The container has no network (``--network none``). This supervisor starts before the MCP
server and records everything the server tries to do, then runs the server with stdin/stdout
passed straight through:

* DNS sinkhole on 127.0.0.1:53 - every lookup is logged (including data smuggled in names)
  and answered with 127.0.0.1, so non-proxy-aware clients connect to ...
* TCP sinks on common ports - the HTTP Host / TLS SNI and any planted canary in the first
  bytes are logged, then the connection is refused
* an HTTP proxy sink (HTTP_PROXY / HTTPS_PROXY) for proxy-aware clients
* inotify on the decoy home - which planted credential files were opened, written or created
* a /proc sampler - every process started inside the container
* command shims (curl, wget, nc, ssh, ...) first on PATH - attempts are logged and refused

Events are appended as JSON lines to ``--out`` so the host can read them while the server runs.
Nothing is ever written to stdout: that stream belongs to the MCP protocol.
"""

from __future__ import annotations

import ctypes
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

OUT = "/sentinel/out/events.jsonl"
CANARY = os.environ.pop("SENTINEL_CANARY", "")  # planted in the decoy credential files
ENV_CANARY = os.environ.pop("SENTINEL_ENV_CANARY", "")  # stands in for the server's own configured secrets
SINK_PORTS = (80, 443, 8080, 8443, 21, 22, 25, 465, 587, 993, 3306, 5432, 6379, 9200, 27017)
PROXY_PORT = 3128
_lock = threading.Lock()


def log(kind: str, **data: object) -> None:
    data["kind"] = kind
    data["t"] = time.time()
    line = json.dumps(data, ensure_ascii=False, default=str)
    with _lock:
        try:
            with open(OUT, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass


def canaries(data: bytes | str) -> dict[str, bool]:
    text = data.decode("latin-1", "replace") if isinstance(data, bytes) else data
    return {"canary": bool(CANARY and CANARY in text), "env_canary": bool(ENV_CANARY and ENV_CANARY in text)}


def warn(message: str) -> None:
    sys.stderr.write(f"[sentinel-sandbox] {message}\n")
    sys.stderr.flush()


# --- network sinks -------------------------------------------------------------------------
def dns_sinkhole() -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 53))
    except OSError as exc:
        log("agent_warning", message=f"dns sinkhole unavailable: {exc}")
        return
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            i, labels = 12, []
            while i < len(data) and data[i] != 0:
                length = data[i]
                labels.append(data[i + 1:i + 1 + length].decode("ascii", "replace"))
                i += 1 + length
            qtype = struct.unpack(">H", data[i + 1:i + 3])[0]
            name = ".".join(labels).lower()
            if qtype in (1, 28):
                log("dns", host=name, qtype=qtype, **canaries(name))
            question = data[12:i + 5]
            answer, count = b"", 0
            if qtype == 1:  # A -> 127.0.0.1 so the follow-up connection lands in a sink
                answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 5, 4) + socket.inet_aton("127.0.0.1")
                count = 1
            header = data[:2] + struct.pack(">HHHHH", 0x8180, 1, count, 0, 0)
            sock.sendto(header + question + answer, addr)
        except Exception:  # noqa: BLE001 - a malformed packet must not stop the sinkhole
            continue


def _sni(buf: bytes) -> str | None:
    try:
        if not buf or buf[0] != 0x16:
            return None
        p = 5 + 4 + 2 + 32
        p += 1 + buf[p]
        p += 2 + struct.unpack(">H", buf[p:p + 2])[0]
        p += 1 + buf[p]
        end = p + 2 + struct.unpack(">H", buf[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack(">HH", buf[p:p + 4])
            p += 4
            if etype == 0:
                name_len = struct.unpack(">H", buf[p + 3:p + 5])[0]
                return buf[p + 5:p + 5 + name_len].decode("ascii", "replace")
            p += elen
    except Exception:  # noqa: BLE001
        return None
    return None


def _read_some(conn: socket.socket, limit: int = 16384, wait: float = 1.5) -> bytes:
    conn.settimeout(wait)
    buf = b""
    try:
        while len(buf) < limit:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            if buf[:1] == b"\x16":
                break
            head, sep, body = buf.partition(b"\r\n\r\n")
            if sep:
                length = 0
                for line in head.split(b"\r\n")[1:]:
                    if line.lower().startswith(b"content-length:"):
                        try:
                            length = int(line.split(b":", 1)[1].strip())
                        except ValueError:
                            length = 0
                if len(body) >= min(length, limit):
                    break
    except OSError:
        pass
    return buf


def _http_host(buf: bytes) -> tuple[str, str, str]:
    text = buf.decode("latin-1", "replace")
    first = text.split("\r\n", 1)[0]
    parts = first.split(" ")
    method = parts[0] if parts and parts[0].isalpha() else ""
    target = parts[1] if len(parts) > 1 else ""
    host = ""
    for line in text.split("\r\n")[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[1].strip()
            break
    return method, target[:200], host


def _sink_conn(conn: socket.socket, port: int) -> None:
    try:
        buf = _read_some(conn)
        sni = _sni(buf)
        method, target, host = ("", "", "") if sni else _http_host(buf)
        log("connect", port=port, host=(sni or host).split(":")[0].lower(), tls=bool(sni), method=method, path=target,
            bytes=len(buf), **canaries(buf))
        if method:
            conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def _proxy_conn(conn: socket.socket) -> None:
    try:
        buf = _read_some(conn)
        method, target, host = _http_host(buf)
        if method == "CONNECT":
            host = target.split(":")[0]
        elif "://" in target:
            host = target.split("/")[2].split(":")[0]
        log("proxy", host=host.lower(), method=method, path=target if method != "CONNECT" else "", **canaries(buf))
        conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
    except OSError:
        pass
    finally:
        conn.close()


def tcp_sink(port: int, handler) -> None:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", port))
        sock.listen(16)
    except OSError:
        return
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            continue
        threading.Thread(target=handler, args=(conn,) if handler is _proxy_conn else (conn, port), daemon=True).start()


# --- file watcher ----------------------------------------------------------------------------
IN_ACCESS, IN_MODIFY, IN_CLOSE_WRITE, IN_OPEN = 0x1, 0x2, 0x8, 0x20
IN_MOVED_TO, IN_CREATE, IN_DELETE, IN_ISDIR = 0x80, 0x100, 0x200, 0x40000000
WATCH_MASK = IN_ACCESS | IN_MODIFY | IN_CLOSE_WRITE | IN_OPEN | IN_MOVED_TO | IN_CREATE | IN_DELETE


def watch_tree(root: str) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        fd = libc.inotify_init1(0o2000000)
        if fd < 0:
            raise OSError(ctypes.get_errno(), "inotify_init1")
    except (OSError, AttributeError) as exc:
        log("agent_warning", message=f"file watcher unavailable: {exc}")
        return
    wds: dict[int, str] = {}

    def add(path: str) -> None:
        wd = libc.inotify_add_watch(fd, path.encode(), WATCH_MASK)
        if wd >= 0:
            wds[wd] = path

    for dirpath, _dirs, _files in os.walk(root):
        add(dirpath)
    last: dict[tuple[str, str], float] = {}
    while True:
        try:
            data = os.read(fd, 65536)
        except OSError:
            return
        i = 0
        while i + 16 <= len(data):
            wd, mask, _cookie, length = struct.unpack("iIII", data[i:i + 16])
            name = data[i + 16:i + 16 + length].rstrip(b"\0").decode("utf-8", "replace")
            i += 16 + length
            base = wds.get(wd, "")
            path = os.path.join(base, name) if name else base
            if mask & IN_ISDIR:
                if mask & IN_CREATE:
                    add(path)
                    log("fs", op="mkdir", path=path)
                continue
            op = ("open" if mask & IN_OPEN else "read" if mask & IN_ACCESS else "create" if mask & (IN_CREATE | IN_MOVED_TO)
                  else "delete" if mask & IN_DELETE else "write")
            now = time.time()
            if now - last.get((op, path), 0) < 0.5:
                continue
            last[(op, path)] = now
            log("fs", op=op, path=path)


# --- processes -------------------------------------------------------------------------------
def process_sampler(self_pid: int) -> None:
    seen: dict[int, tuple[str, str]] = {}  # pid -> (name, cmdline); re-logged when exec changes it
    while True:
        try:
            pids = [int(d) for d in os.listdir("/proc") if d.isdigit() and int(d) != self_pid]
        except OSError:
            pids = []
        for pid in pids:
            try:
                with open(f"/proc/{pid}/comm", encoding="utf-8") as fh:
                    name = fh.read().strip()
                with open(f"/proc/{pid}/cmdline", "rb") as fh:
                    cmd = fh.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()[:300]
                with open(f"/proc/{pid}/stat", encoding="utf-8") as fh:
                    ppid = int(fh.read().rsplit(")", 1)[1].split()[1])
            except (OSError, ValueError, IndexError):
                continue
            if not cmd or seen.get(pid) == (name, cmd):
                continue  # not exec'd yet, or already reported
            seen[pid] = (name, cmd)
            log("proc", pid=pid, ppid=ppid, name=name, cmd=cmd)
        time.sleep(0.05)


def main(argv: list[str]) -> int:
    global OUT
    watch: list[str] = []
    shims = ""
    while argv and argv[0] != "--":
        flag = argv.pop(0)
        if flag == "--out":
            OUT = argv.pop(0)
        elif flag == "--watch":
            watch.append(argv.pop(0))
        elif flag == "--shims":
            shims = argv.pop(0)
    if not argv or argv[0] != "--" or len(argv) < 2:
        warn("usage: agent.py [--out FILE] [--watch DIR] [--shims DIR] -- command [args...]")
        return 2
    command = argv[1:]
    threading.Thread(target=dns_sinkhole, daemon=True).start()
    for port in SINK_PORTS:
        threading.Thread(target=tcp_sink, args=(port, _sink_conn), daemon=True).start()
    threading.Thread(target=tcp_sink, args=(PROXY_PORT, _proxy_conn), daemon=True).start()
    for path in watch:
        threading.Thread(target=watch_tree, args=(path,), daemon=True).start()
    threading.Thread(target=process_sampler, args=(os.getpid(),), daemon=True).start()
    time.sleep(0.15)  # sinks listening before the server starts
    env = dict(os.environ)
    proxy = f"http://127.0.0.1:{PROXY_PORT}"
    env.update({"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy, "ALL_PROXY": proxy,
                "NO_PROXY": "", "no_proxy": "", "NODE_USE_ENV_PROXY": "1", "SENTINEL_EVENTS": OUT})
    if shims:
        env["PATH"] = shims + os.pathsep + env.get("PATH", "")
    log("ready", command=command[:6])
    try:
        child = subprocess.Popen(command, env=env)
    except OSError as exc:
        log("exit", code=127, error=str(exc))
        warn(f"cannot start {command[0]}: {exc}")
        return 127

    def forward(signum, _frame):
        try:
            child.send_signal(signum)
        except OSError:
            pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    code = child.wait()
    time.sleep(0.1)
    log("exit", code=code)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
