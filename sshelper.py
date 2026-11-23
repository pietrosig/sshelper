#!/bin/sh
''''exec sh -c 'script=$1; shift; for py in "${SSHELPER_PYTHON:-}" python3.14 python3.13 python3.12 python3.11 python3; do [ -n "$py" ] || continue; "$py" -c "import sys; raise SystemExit(sys.version_info < (3, 11))" >/dev/null 2>&1 || continue; exec "$py" "$script" "$@"; done; echo "sshelper: Python 3.11+ is required" >&2; exit 127' sh "$0" "$@" # '''
# sshelper: control ssh port forwards and view remote files from your laptop.
# Single-file, standard-library-only tool. See README.md / SPEC.md.

from __future__ import annotations

import argparse
import curses
import fcntl
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


__version__ = "0.1.0"
APP_MARKER = "sshelper: ssh port forwards and remote file viewer"
GITHUB_REPO = "pietrosig/sshelper"
RELEASE_ASSET_NAME = "sshelper"
LATEST_RELEASE_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
LATEST_RELEASE_ASSET_URL = (
    f"https://github.com/{GITHUB_REPO}/releases/latest/download/{RELEASE_ASSET_NAME}"
)

DASHBOARD_HOST = "ssh.localhost"
DEFAULT_PORT = 9100
SSH_CONFIG_BEGIN = "# >>> sshelper managed >>>"
SSH_CONFIG_END = "# <<< sshelper managed <<<"
SSH_CONFIG_BLOCK = f"""{SSH_CONFIG_BEGIN}
# Lets sshelper control your ssh connections (port forwards, file viewing).
# Remove with: sshelper setup --undo
Host * !github.com !gitlab.com !bitbucket.org
    ControlMaster auto
    ControlPath ~/.ssh/cm/%C
    ControlPersist 10m
{SSH_CONFIG_END}
"""
SYSCTL_FILE = Path("/etc/sysctl.d/50-sshelper.conf")
SYSCTL_KEY = "net.ipv4.ip_unprivileged_port_start"
REMOTE_DIR = "$HOME/.sshelper"

DEFAULT_SETTINGS: dict = {
    "port": DEFAULT_PORT,
    "browser": "",
    "control_dirs": ["~/.ssh/cm"],
    "push_channel": True,
    "push_disabled_hosts": [],
    "agent_skill_hosts": [],
    "retention_days": 60,
    "retention_count": 1000,
}

SCAN_INTERVAL = 2.0
DETECT_INTERVAL = 10.0
PUSH_BODY_LIMIT = 64 * 1024
PROJECT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


# ---------------------------------------------------------------------------
# paths, settings, small helpers
# ---------------------------------------------------------------------------


def config_dir() -> Path:
    env = os.environ.get("SSHELPER_CONFIG_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "sshelper"


def state_dir() -> Path:
    env = os.environ.get("SSHELPER_STATE_DIR")
    if env:
        return Path(env).expanduser()
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "sshelper"


def ensure_private_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        path.chmod(0o700)
    except OSError:
        pass
    return path


def settings_path() -> Path:
    return config_dir() / "settings.json"


def load_settings() -> dict:
    settings = json.loads(json.dumps(DEFAULT_SETTINGS))
    try:
        data = json.loads(settings_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}
    if isinstance(data, dict):
        for key, default in DEFAULT_SETTINGS.items():
            if key in data and isinstance(data[key], type(default)):
                settings[key] = data[key]
    try:
        settings["port"] = int(settings["port"])
    except (TypeError, ValueError):
        settings["port"] = DEFAULT_PORT
    return settings


def save_settings(settings: dict) -> None:
    write_json_atomic(settings_path(), {k: settings.get(k, v) for k, v in DEFAULT_SETTINGS.items()})


def write_json_atomic(path: Path, data: object, mode: int = 0o600) -> None:
    ensure_private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_json(path: Path, default: object) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def dashboard_url(port: int, path: str = "/") -> str:
    host = DASHBOARD_HOST if port == 80 else f"{DASHBOARD_HOST}:{port}"
    return f"http://{host}{path}"


def slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9_-]+", "-", text.lower()).strip("-")
    return slug or "host"


def port_is_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def find_free_port(start: int) -> int:
    port = max(1024, start)
    while port < 65535:
        if port_is_free(port):
            return port
        port += 1
    raise RuntimeError("no free local port")


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# ---------------------------------------------------------------------------
# ssh plumbing (everything goes over existing ControlMaster sockets)
# ---------------------------------------------------------------------------

# Never let one of our ssh calls open a brand-new connection: if the master is
# gone, ProxyCommand=false makes the call fail immediately instead.
MUX_OPTS = [
    "-o", "ControlMaster=no",
    "-o", "ProxyCommand=false",
    "-o", "BatchMode=yes",
    "-o", "LogLevel=ERROR",
]
SSH_OPTS_WITH_ARG = set("BbcDEeFIiJLlmOoPpQRSWw")


def ssh_mux(sock: str, *args: str, dest: str = "sshelper", timeout: float = 15,
            input: bytes | None = None) -> subprocess.CompletedProcess:
    cmd = ["ssh", "-S", sock, *MUX_OPTS, *args, dest or "sshelper"]
    return subprocess.run(cmd, input=input, capture_output=True, timeout=timeout)


def remote_script(script: str) -> str:
    """Wrap a POSIX sh script so it survives any remote login shell."""
    # fish treats \\ inside single quotes as an escape; keep scripts free of it.
    assert "\\\\" not in script, "remote scripts must not contain double backslashes"
    return "sh -c " + shlex.quote(script)


def remote_run(sock: str, dest: str, script: str, *, timeout: float = 20,
               input: bytes | None = None) -> subprocess.CompletedProcess:
    cmd = ["ssh", "-S", sock, *MUX_OPTS, "-T", dest or "sshelper", remote_script(script)]
    return subprocess.run(cmd, input=input, capture_output=True, timeout=timeout)


def remote_popen(sock: str, dest: str, script: str, *, stdin_pipe: bool = False
                 ) -> subprocess.Popen:
    cmd = ["ssh", "-S", sock, *MUX_OPTS, "-T", dest or "sshelper", remote_script(script)]
    return subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_pipe else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)


def mux_check(sock: str) -> int | None:
    try:
        proc = ssh_mux(sock, "-O", "check", timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    match = re.search(rb"pid=(\d+)", proc.stderr + proc.stdout)
    return int(match.group(1)) if match else None


def process_argv(pid: int) -> list[str]:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return [part.decode(errors="replace") for part in raw.split(b"\0") if part]
    except OSError:
        pass
    try:
        out = subprocess.run(["ps", "-ww", "-o", "args=", "-p", str(pid)],
                             capture_output=True, text=True, timeout=5).stdout
        return shlex.split(out.strip())
    except (OSError, ValueError, subprocess.SubprocessError):
        return []


def ssh_destination_index(argv: list[str]) -> int | None:
    """Index of the destination in an `ssh ...` argv (None if there is none)."""
    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            i += 1
            break
        if arg.startswith("-") and len(arg) > 1:
            for j in range(1, len(arg)):
                if arg[j] in SSH_OPTS_WITH_ARG:
                    if j + 1 == len(arg):
                        i += 1  # the option value is the next token
                    break
            i += 1
            continue
        break
    return i if i < len(argv) else None


def parse_ssh_destination(argv: list[str]) -> str | None:
    """Return the destination of an `ssh ...` command line."""
    idx = ssh_destination_index(argv)
    return argv[idx] if idx is not None else None


def ssh_processes() -> list[tuple[int, list[str]]]:
    """(pid, argv) of this user's `ssh` client processes."""
    result: list[tuple[int, list[str]]] = []
    proc_root = Path("/proc")
    if proc_root.is_dir():
        uid = os.getuid()
        for entry in proc_root.iterdir():
            if not entry.name.isdigit():
                continue
            try:
                if entry.stat().st_uid != uid:
                    continue
                raw = (entry / "cmdline").read_bytes()
            except OSError:
                continue
            argv = [part.decode(errors="replace") for part in raw.split(b"\0") if part]
            if argv and os.path.basename(argv[0]) == "ssh":
                result.append((int(entry.name), argv))
        return result
    try:
        out = subprocess.run(["ps", "-u", str(os.getuid()), "-o", "pid=,args="],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return result
    for line in out.splitlines():
        pid_text, _, args = line.strip().partition(" ")
        argv = args.split()
        if pid_text.isdigit() and argv and os.path.basename(argv[0]) == "ssh":
            result.append((int(pid_text), argv))
    return result


def is_our_ssh(argv: list[str]) -> bool:
    """True for ssh calls made by sshelper itself or other non-session calls."""
    return ("-O" in argv or "-G" in argv or "-W" in argv
            or any("ProxyCommand=false" in arg for arg in argv))


def resolve_control_path(argv: list[str]) -> str | None:
    """Ask ssh which ControlPath this exact command line uses (handles wrappers
    like kitty's `kitten ssh` that pass -o ControlPath=... themselves)."""
    idx = ssh_destination_index(argv)
    if idx is None:
        return None
    try:
        out = subprocess.run(["ssh", "-G", *argv[1:idx], argv[idx]], stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        if line.startswith("controlpath "):
            value = line.split(" ", 1)[1].strip()
            return None if value == "none" else value
    return None


def is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.lstat(path).st_mode)
    except OSError:
        return False


def ssh_config_aliases() -> list[str]:
    """Concrete Host aliases from ~/.ssh/config (no wildcards or negations)."""
    aliases: list[str] = []
    try:
        lines = (Path.home() / ".ssh" / "config").read_text(errors="replace").splitlines()
    except OSError:
        return aliases
    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].lower() == "host":
            for name in parts[1:]:
                if not any(ch in name for ch in "*?!") and name not in aliases:
                    aliases.append(name)
    return aliases


def ssh_g(dest: str) -> dict[str, str]:
    try:
        out = subprocess.run(["ssh", "-G", dest], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    info: dict[str, str] = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        info.setdefault(key.lower(), value)
    return info


def local_listeners() -> list[dict]:
    """Listening TCP sockets on the laptop with owning pid (own processes)."""
    result: list[dict] = []
    try:
        out = subprocess.run(["ss", "-tlnpH"], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        out = ""
    if out:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            addr = parts[3]
            port = addr.rsplit(":", 1)[-1]
            for name, pid in re.findall(r'\("([^"]+)",pid=(\d+)', line):
                if port.isdigit():
                    result.append({"port": int(port), "pid": int(pid), "proc": name,
                                   "addr": addr})
        return result
    try:
        out = subprocess.run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-Fpcn"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return result
    pid, proc = 0, ""
    for line in out.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("c"):
            proc = line[1:]
        elif line.startswith("n"):
            port = line.rsplit(":", 1)[-1]
            if port.isdigit():
                result.append({"port": int(port), "pid": pid, "proc": proc, "addr": line[1:]})
    return result


def master_peer_ip(pid: int) -> str:
    try:
        out = subprocess.run(["ss", "-tnpH"], capture_output=True, text=True,
                             timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""
    for line in out.splitlines():
        if f"pid={pid}," in line:
            parts = line.split()
            if len(parts) >= 5:
                return parts[4].rsplit(":", 1)[0].strip("[]")
    return ""


DETECT_SCRIPT = "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null"


def parse_remote_listeners(text: str) -> list[dict]:
    found: dict[int, dict] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        if parts[0] == "LISTEN":
            local = parts[3]
            match = re.search(r'\("([^"]+)",pid=(\d+)', line)
            if not match:
                continue
            proc, pid = match.group(1), int(match.group(2))
        elif parts[0].startswith("tcp") and len(parts) >= 7:
            local = parts[3]
            owner = parts[-1]
            if "/" not in owner:
                continue
            pid_text, _, proc = owner.partition("/")
            if not pid_text.isdigit():
                continue
            pid = int(pid_text)
        else:
            continue
        host, _, port_text = local.rpartition(":")
        if not port_text.isdigit() or proc.startswith("sshd"):
            continue
        host = host.strip("[]")
        loopback_or_any = host in {"", "*", "0.0.0.0", "::", "127.0.0.1", "::1", "localhost"} \
            or host.startswith("127.")
        port = int(port_text)
        if port in found and found[port]["target"] == "localhost":
            continue
        found[port] = {
            "port": port,
            "pid": pid,
            "proc": proc,
            "bind": host or "*",
            "target": "localhost" if loopback_or_any else host,
        }
    return sorted(found.values(), key=lambda item: item["port"])


def describe_cmdline(cmdline: str, fallback: str) -> str:
    try:
        tokens = shlex.split(cmdline)
    except ValueError:
        tokens = cmdline.split()
    if not tokens:
        return fallback
    prog = os.path.basename(tokens[0])
    if prog.endswith(":"):  # rewritten process titles like "ssh: /path [mux]"
        return fallback
    if prog.startswith("python") or prog in {"node", "bun", "deno", "ruby", "julia"}:
        rest = tokens[1:]
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok == "-m" and i + 1 < len(rest):
                return f"{prog} -m {rest[i + 1]}"
            if not tok.startswith("-"):
                return f"{prog} {os.path.basename(tok)}"
            i += 1
    return prog


def guess_mime(path: str) -> str:
    mime, _ = mimetypes.guess_type(path)
    lower = path.lower()
    text_ext = (".log", ".out", ".err", ".md", ".yaml", ".yml", ".toml", ".cfg",
                ".ini", ".py", ".sh", ".txt", ".csv", ".tsv", ".rst", ".conf")
    if lower.endswith(text_ext):
        return "text/plain; charset=utf-8"
    if lower.endswith(".mkv"):
        return "video/x-matroska"
    if mime is None:
        return "application/octet-stream"
    if mime.startswith("text/") and mime != "text/html":
        return "text/plain; charset=utf-8"
    if mime == "text/html":
        return "text/html; charset=utf-8"
    return mime


# ---------------------------------------------------------------------------
# daemon state
# ---------------------------------------------------------------------------


def log(message: str) -> None:
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{stamp}] {message}", file=sys.stderr, flush=True)


@dataclass
class Conn:
    sock: str
    pid: int
    dest: str
    id: str
    ip: str = ""
    ssh_host: str = ""
    user: str = ""
    rhost: str = ""
    rhome: str = ""
    status: str = "connecting"  # connecting | ok | noshell
    local_fwd: str = "unknown"  # unknown | ok | blocked  (-L)
    remote_fwd: str = "unknown"  # unknown | ok | blocked (-R)
    error: str = ""
    push_server: ThreadingHTTPServer | None = None
    push_lport: int = 0
    push_rport: int = 0
    push_token: str = ""
    push_error: str = ""
    push_ready: bool = False
    skill: str = ""  # "" | installed | removed | error: ...
    forwards: list = field(default_factory=list)
    detected: list = field(default_factory=list)
    detected_at: float = 0.0
    misses: int = 0
    since: float = field(default_factory=time.time)

    def public(self) -> dict:
        return {
            "id": self.id,
            "dest": self.dest,
            "ip": self.ip,
            "ssh_host": self.ssh_host,
            "user": self.user,
            "rhost": self.rhost,
            "home": self.rhome,
            "status": self.status,
            "local_fwd": self.local_fwd,
            "remote_fwd": self.remote_fwd,
            "error": self.error,
            "skill": self.skill,
            "push": {
                "ok": bool(self.push_rport and self.push_ready),
                "port": self.push_rport,
                "error": self.push_error,
            },
            "forwards": self.forwards,
            "detected": self.detected,
            "since": self.since,
        }


def parse_sshd_forwarding(lines: list[str]) -> tuple[str, str]:
    """(local, remote) forwarding status from global sshd_config lines."""
    local, remote = "unknown", "unknown"
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        key, value = parts[0].lower(), parts[1].lower()
        if key == "disableforwarding" and value == "yes":
            return "blocked", "blocked"
        if key == "allowtcpforwarding":
            local = "blocked" if value in {"no", "remote"} else "ok"
            remote = "blocked" if value in {"no", "local"} else "ok"
            break  # sshd uses the first value it reads
    return local, remote


INBOX_MARK = "@@SSHELPER-INBOX@@"
INBOX_SCRIPT = (
    'd="/tmp/sshelper-$(id -u)/inbox"; [ -d "$d" ] && [ -O "$d" ] || exit 0; '
    'for f in "$d"/*.json; do [ -f "$f" ] || continue; c="$f.$$.claim"; '
    'mv "$f" "$c" 2>/dev/null || continue; '
    f'echo "{INBOX_MARK}"; head -c 65536 "$c"; echo; rm -f "$c"; done'
)

INFO_SCRIPT = (
    'id -un; uname -n; echo "$HOME"; '
    "grep -h -i -E '^(allowtcpforwarding|disableforwarding)[[:space:]]' "
    "/etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | head -n 5; true"
)


def stat_script(paths: list[str]) -> str:
    quoted = " ".join(shlex.quote(p) for p in paths)
    return (
        f"for p in {quoted}; do "
        'if [ -d "$p" ]; then echo "d 0 0"; '
        'elif [ -f "$p" ]; then '
        's=$(stat -L -c "%s %Y" "$p" 2>/dev/null || stat -L -f "%z %m" "$p" 2>/dev/null); '
        'echo "f $s"; '
        'elif [ -e "$p" ]; then echo "o 0 0"; '
        'else echo "n 0 0"; fi; done'
    )


KIND_NAMES = {"d": "dir", "f": "file", "o": "other", "n": "missing"}


def parse_stat_output(text: str, count: int) -> list[dict]:
    result = []
    lines = text.splitlines()
    for idx in range(count):
        parts = lines[idx].split() if idx < len(lines) else []
        kind = KIND_NAMES.get(parts[0], "missing") if parts else "missing"
        try:
            size = int(parts[1]) if len(parts) > 1 else 0
            mtime = int(float(parts[2])) if len(parts) > 2 else 0
        except ValueError:
            size, mtime = 0, 0
        result.append({"kind": kind, "size": size, "mtime": mtime})
    return result


def build_push(payload: object, conn: Conn) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("body must be a JSON object")
    project = str(payload.get("project") or "").strip().lower().replace(" ", "-")
    if not PROJECT_RE.match(project):
        raise ValueError("'project' is required: lowercase letters, digits, '-' or '_' (max 63)")
    items_in = payload.get("items")
    if items_in is None:
        single = {k: payload[k] for k in ("path", "port", "text", "url", "caption", "name", "host")
                  if k in payload}
        items_in = [single] if single else []
    if not isinstance(items_in, list) or not items_in:
        raise ValueError("'items' must be a non-empty list")
    if len(items_in) > 100:
        raise ValueError("at most 100 items per push")
    items = []
    for raw in items_in:
        if not isinstance(raw, dict):
            raise ValueError("each item must be a JSON object")
        if "path" in raw:
            path = str(raw["path"])
            if path == "~" or path.startswith("~/"):
                path = conn.rhome + path[1:]
            if not path.startswith("/"):
                raise ValueError(f"path must be absolute: {path!r}")
            norm = os.path.normpath(path)
            if path.endswith("/") and norm != "/":
                norm += "/"
            item: dict = {"type": "path", "path": norm}
        elif "port" in raw:
            try:
                port = int(raw["port"])
            except (TypeError, ValueError):
                raise ValueError("port must be a number") from None
            if not 1 <= port <= 65535:
                raise ValueError("port must be 1-65535")
            item = {"type": "port", "port": port, "host": str(raw.get("host") or "localhost")[:100]}
        elif "text" in raw:
            item = {"type": "text", "text": str(raw["text"])[:20000]}
        elif "url" in raw:
            url = str(raw["url"])
            if not url.startswith(("http://", "https://")):
                raise ValueError("url must start with http:// or https://")
            item = {"type": "url", "url": url[:2000]}
        else:
            raise ValueError("each item needs one of: path, port, text, url")
        caption = raw.get("caption") or raw.get("name")
        if caption:
            item["caption"] = str(caption)[:200]
        items.append(item)
    return {
        "id": secrets.token_hex(6),
        "time": time.time(),
        "project": project,
        "title": str(payload.get("title") or "")[:200],
        "sender": str(payload.get("sender") or "")[:80],
        "items": items,
        "from": {
            "conn": conn.id,
            "dest": conn.dest,
            "ip": conn.ip,
            "user": conn.user,
            "host": conn.rhost,
        },
    }


class Daemon:
    def __init__(self, settings: dict):
        self.settings = settings
        self.lock = threading.RLock()
        self.changed = threading.Condition()
        self.version = 0
        self.stop = threading.Event()
        self.conns: dict[str, Conn] = {}  # by control socket path
        self.uncontrolled: list[dict] = []
        self.session = secrets.token_hex(16)
        self.laptop = socket.gethostname()
        self.port = 0
        self.scans = 0
        self.notice = ""
        self._cp_cache: dict[tuple, str | None] = {}
        self.dest_hints: dict[str, str] = {}
        self._alias_map: dict[str, str] = {}
        self._alias_map_mtime = -1.0
        self.forwards_file = state_dir() / "forwards.json"
        data = read_json(self.forwards_file, {})
        data = data if isinstance(data, dict) else {}
        self.pins: dict[str, list[dict]] = data.get("pins") or {}
        self.tracked: dict[str, dict[str, dict]] = data.get("tracked") or {}
        self.pushes_file = state_dir() / "pushes.jsonl"
        self.pushes: list[dict] = self._load_pushes()

    # -- change notification ------------------------------------------------

    def bump(self) -> None:
        with self.changed:
            self.version += 1
            self.changed.notify_all()

    def wait_change(self, version: int, timeout: float) -> int:
        with self.changed:
            self.changed.wait_for(lambda: self.version != version or self.stop.is_set(), timeout)
            return self.version

    # -- persistence ----------------------------------------------------------

    def _save_forwards(self) -> None:
        live = {str(c.pid) for c in self.conns.values()}
        self.tracked = {pid: v for pid, v in self.tracked.items() if pid in live and v}
        try:
            write_json_atomic(self.forwards_file, {"pins": self.pins, "tracked": self.tracked})
        except OSError as exc:
            log(f"cannot save forwards: {exc}")

    def _load_pushes(self) -> list[dict]:
        pushes = []
        try:
            with self.pushes_file.open(encoding="utf-8") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(record, dict) and record.get("id"):
                        pushes.append(record)
        except OSError:
            pass
        kept = self._apply_retention(pushes)
        if len(kept) != len(pushes):
            self._rewrite_pushes(kept)
        return kept

    def _apply_retention(self, pushes: list[dict]) -> list[dict]:
        cutoff = time.time() - self.settings["retention_days"] * 86400
        pushes = [p for p in pushes if float(p.get("time") or 0) >= cutoff]
        return pushes[-self.settings["retention_count"]:]

    def _rewrite_pushes(self, pushes: list[dict]) -> None:
        ensure_private_dir(self.pushes_file.parent)
        tmp = self.pushes_file.with_name(f".{self.pushes_file.name}.tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            for record in pushes:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.pushes_file)

    # -- scanning ---------------------------------------------------------------

    def control_sockets(self) -> list[str]:
        """Sockets in control_dirs plus sockets used by running ssh processes."""
        socks = []
        seen_keys = set()
        for pid, argv in ssh_processes():
            if is_our_ssh(argv):
                continue
            key = tuple(argv)
            seen_keys.add(key)
            if key not in self._cp_cache:
                self._cp_cache[key] = resolve_control_path(argv)
            path = self._cp_cache[key]
            if path and is_socket(path):
                socks.append(path)
                dest = parse_ssh_destination(argv)
                if dest:
                    self.dest_hints[path] = dest
        self._cp_cache = {k: v for k, v in self._cp_cache.items() if k in seen_keys}
        # Masters that outlive their terminal (ControlPersist) stay visible.
        socks.extend(path for path in [*self.conns, *self.dest_hints] if is_socket(path))
        for raw in self.settings["control_dirs"]:
            directory = Path(raw).expanduser()
            try:
                entries = list(directory.iterdir())
            except OSError:
                continue
            for entry in entries:
                try:
                    if stat.S_ISSOCK(entry.lstat().st_mode):
                        socks.append(str(entry))
                except OSError:
                    continue
        return sorted(set(socks))

    def _dest_for(self, sock: str, pid: int) -> str | None:
        if sock in self.dest_hints:
            return self.dest_hints[sock]
        # Persisted master whose terminal is gone: match ~/.ssh/config aliases.
        try:
            mtime = (Path.home() / ".ssh" / "config").stat().st_mtime
        except OSError:
            mtime = 0.0
        if self._alias_map_mtime != mtime:
            mapping = {}
            for alias in ssh_config_aliases():
                path = ssh_g(alias).get("controlpath")
                if path and path != "none":
                    mapping.setdefault(path, alias)
            self._alias_map, self._alias_map_mtime = mapping, mtime
        if sock in self._alias_map:
            return self._alias_map[sock]
        argv = process_argv(pid)
        if argv and os.path.basename(argv[0]) == "ssh":  # master kept its argv
            return parse_ssh_destination(argv)
        return None

    def scan_loop(self) -> None:
        while not self.stop.is_set():
            try:
                self.scan_once()
            except Exception as exc:  # keep the daemon alive no matter what
                log(f"scan error: {exc!r}")
            self.stop.wait(SCAN_INTERVAL)

    def scan_once(self) -> None:
        alive: dict[str, int] = {}
        for sock in self.control_sockets():
            pid = mux_check(sock)
            if pid:
                alive[sock] = pid
        changed = False
        new: list[Conn] = []
        with self.lock:
            for sock, conn in list(self.conns.items()):
                pid = alive.get(sock)
                if pid == conn.pid:
                    conn.misses = 0
                    continue
                if pid is None and is_socket(sock) and conn.misses < 2:
                    conn.misses += 1  # one slow check is not a disconnect
                    continue
                self._drop(conn)
                changed = True
            for sock, pid in alive.items():
                if sock not in self.conns:
                    conn = self._make_conn(sock, pid)
                    self.conns[sock] = conn
                    new.append(conn)
                    changed = True
        for conn in new:
            log(f"connection {conn.id} ({conn.dest}, pid {conn.pid})")
            threading.Thread(target=self._init_conn, args=(conn,), daemon=True).start()

        listeners = local_listeners()
        with self.lock:
            for conn in self.conns.values():
                forwards = self._forwards_for(conn, listeners)
                if forwards != conn.forwards:
                    conn.forwards = forwards
                    self._mark_detected(conn)
                    changed = True
            uncontrolled = self._find_uncontrolled()
            if uncontrolled != self.uncontrolled:
                self.uncontrolled = uncontrolled
                changed = True
            due = [c for c in self.conns.values()
                   if c.status == "ok" and time.time() - c.detected_at > DETECT_INTERVAL]
        for conn in due:
            if self._detect(conn):
                changed = True
        with self.lock:
            ready = [c for c in self.conns.values() if c.status == "ok"]
        for conn in ready:
            self._collect_inbox(conn)
        self.scans += 1
        if changed or self.scans == 1:
            self.bump()

    def _unique_id(self, dest: str, conn: Conn | None = None) -> str:
        base = slugify(dest.split("@")[-1].replace("ssh://", ""))
        used = {c.id for c in self.conns.values() if c is not conn}
        conn_id, n = base, 2
        while conn_id in used:
            conn_id, n = f"{base}-{n}", n + 1
        return conn_id

    def _make_conn(self, sock: str, pid: int) -> Conn:
        dest = self._dest_for(sock, pid)
        if dest:
            return Conn(sock=sock, pid=pid, dest=dest, id=self._unique_id(dest))
        # Unknown for now; named after the remote hostname once we reach it.
        return Conn(sock=sock, pid=pid, dest="", id=self._unique_id(f"conn-{pid}"))

    def _drop(self, conn: Conn) -> None:
        log(f"connection {conn.id} gone")
        self.conns.pop(conn.sock, None)
        self._stop_push_server(conn)
        # Another connection to the same machine: point the endpoint file at it,
        # otherwise it keeps naming the port of the connection that just closed.
        for other in self.conns.values():
            if other.rhost and other.rhost == conn.rhost and other.push_ready:
                log(f"{other.id}: taking over the push endpoint of {conn.id}")
                threading.Thread(target=self._write_remote_endpoint, args=(other,),
                                 daemon=True).start()
                break

    def _collect_inbox(self, conn: Conn) -> None:
        """Pushes queued as files by agents that cannot reach the port (sandboxes)."""
        try:
            proc = remote_run(conn.sock, conn.dest, INBOX_SCRIPT, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return
        text = proc.stdout.decode(errors="replace")
        for chunk in text.split(INBOX_MARK + "\n")[1:]:
            try:
                self.add_push(conn, json.loads(chunk.strip()), via="inbox")
            except (ValueError, json.JSONDecodeError) as exc:
                log(f"{conn.id}: rejected queued push: {exc}")

    def _alive(self, conn: Conn) -> bool:
        with self.lock:
            return self.conns.get(conn.sock) is conn

    def _init_conn(self, conn: Conn) -> None:
        info = ssh_g(conn.dest) if conn.dest else {}
        conn.ssh_host = info.get("hostname", "")
        conn.ip = master_peer_ip(conn.pid) or conn.ssh_host
        try:
            proc = remote_run(conn.sock, conn.dest, INFO_SCRIPT, timeout=20)
            lines = proc.stdout.decode(errors="replace").splitlines()
        except (OSError, subprocess.SubprocessError) as exc:
            proc, lines = None, []
            conn.error = str(exc)
        if proc is None or proc.returncode != 0 or len(lines) < 3:
            conn.status = "noshell"
            if proc is not None:
                conn.error = proc.stderr.decode(errors="replace").strip()[:300]
            self.bump()
            return
        conn.user, conn.rhost, conn.rhome = lines[0], lines[1], lines[2]
        if not conn.dest:
            with self.lock:
                conn.dest = conn.rhost
                conn.id = self._unique_id(conn.rhost, conn)
        conn.local_fwd, conn.remote_fwd = parse_sshd_forwarding(lines[3:])
        conn.status = "ok"
        self.bump()
        if not self._alive(conn):
            return
        self._restore_pins(conn)
        disabled = set(self.settings["push_disabled_hosts"])
        if self.settings["push_channel"] and conn.dest not in disabled and conn.id not in disabled:
            self._setup_push(conn)
        self._detect(conn)
        self.bump()

    def _find_uncontrolled(self) -> list[dict]:
        try:
            out = subprocess.run(["ps", "-u", str(os.getuid()), "-o", "pid=,args="],
                                 capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return []
        masters = {c.pid for c in self.conns.values()}
        dests = {c.dest for c in self.conns.values()}
        skip_words = ("ProxyCommand=false", "git-upload-pack", "git-receive-pack",
                      "git-lfs", "rsync --server", "scp -", "sftp")
        found: dict[str, dict] = {}
        for line in out.splitlines():
            pid_text, _, args = line.strip().partition(" ")
            argv = args.split()
            if not pid_text.isdigit() or not argv or os.path.basename(argv[0]) != "ssh":
                continue
            if int(pid_text) in masters or "-O" in argv or "-W" in argv or "-G" in argv:
                continue
            if any(word in args for word in skip_words):
                continue
            dest = parse_ssh_destination(argv)
            if not dest or dest in dests or dest in found:
                continue
            found[dest] = {"pid": int(pid_text), "dest": dest}
        return sorted(found.values(), key=lambda item: item["dest"])

    # -- forwards ---------------------------------------------------------------

    def _forwards_for(self, conn: Conn, listeners: list[dict]) -> list[dict]:
        ports = sorted({item["port"] for item in listeners if item["pid"] == conn.pid})
        tracked = self.tracked.get(str(conn.pid), {})
        pins = self.pins.get(conn.dest, [])
        result = []
        for port in ports:
            info = tracked.get(str(port))
            pinned = any(pin.get("local") == port for pin in pins)
            result.append({
                "local": port,
                "target": info["target"] if info else None,
                "rport": info["rport"] if info else None,
                "external": info is None,
                "pinned": pinned,
            })
        return result

    def _mark_detected(self, conn: Conn) -> None:
        by_target = {(f["target"], f["rport"]): f["local"] for f in conn.forwards if f["rport"]}
        for item in conn.detected:
            item["forwarded_local"] = by_target.get((item["target"], item["port"]))

    def _detect(self, conn: Conn) -> bool:
        conn.detected_at = time.time()
        try:
            proc = remote_run(conn.sock, conn.dest, DETECT_SCRIPT, timeout=10)
        except (OSError, subprocess.SubprocessError):
            return False
        items = [i for i in parse_remote_listeners(proc.stdout.decode(errors="replace"))
                 if i["port"] != conn.push_rport]
        pids = sorted({i["pid"] for i in items})
        names: dict[int, str] = {}
        if pids:
            script = ("for p in " + " ".join(map(str, pids)) + "; do printf '%s ' \"$p\"; "
                      "tr '\\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo; done")
            try:
                out = remote_run(conn.sock, conn.dest, script, timeout=10).stdout
                for line in out.decode(errors="replace").splitlines():
                    pid_text, _, cmdline = line.partition(" ")
                    if pid_text.isdigit():
                        names[int(pid_text)] = cmdline.strip()
            except (OSError, subprocess.SubprocessError):
                pass
        for item in items:
            item["name"] = describe_cmdline(names.get(item["pid"], ""), item["proc"])
        with self.lock:
            old = [{k: v for k, v in d.items() if k != "forwarded_local"} for d in conn.detected]
            conn.detected = items
            self._mark_detected(conn)
            return old != items

    def find_conn(self, key: str) -> Conn:
        with self.lock:
            conns = list(self.conns.values())
        for attr in ("id", "dest", "rhost", "ssh_host"):
            for conn in conns:
                if getattr(conn, attr) == key:
                    return conn
        raise LookupError(f"no controllable connection named {key!r}")

    def open_forward(self, conn: Conn, rport: int, target: str = "localhost",
                     local: int | None = None, pin: bool = False) -> int:
        if not 1 <= rport <= 65535:
            raise ValueError("remote port must be 1-65535")
        target = target or "localhost"
        if target.isdigit():
            raise ValueError(f"{target!r} is not a host; for remote:local ports use PORT:LOCAL")
        if not re.match(r"^[A-Za-z0-9._:-]+$", target):
            raise ValueError("invalid target host")
        wanted = local or rport
        if local is not None:
            if not port_is_free(local):
                raise RuntimeError(f"local port {local} is already in use")
        elif wanted < 1024 or not port_is_free(wanted):
            wanted = find_free_port(wanted + 1 if wanted >= 1024 else 8000 + wanted)
        spec = f"127.0.0.1:{wanted}:{target}:{rport}"
        proc = ssh_mux(conn.sock, "-O", "forward", "-L", spec, dest=conn.dest)
        if proc.returncode != 0:
            message = (proc.stderr + proc.stdout).decode(errors="replace").strip()
            raise RuntimeError(message or "ssh refused the forward")
        with self.lock:
            self.tracked.setdefault(str(conn.pid), {})[str(wanted)] = {
                "rport": rport, "target": target, "local": wanted}
            if pin:
                self._set_pin(conn, rport, target, wanted, True)
            self._save_forwards()
        log(f"{conn.id}: forward localhost:{wanted} -> {target}:{rport}")
        self.refresh_forwards()
        return wanted

    def close_forward(self, conn: Conn, local: int) -> None:
        info = self.tracked.get(str(conn.pid), {}).get(str(local))
        if info:
            specs = [f"127.0.0.1:{local}:{info['target']}:{info['rport']}"]
        else:
            specs = [f"{prefix}{local}:{host}:{local}"
                     for prefix in ("", "127.0.0.1:", "localhost:")
                     for host in ("localhost", "127.0.0.1")]
        error = ""
        for spec in specs:
            proc = ssh_mux(conn.sock, "-O", "cancel", "-L", spec, dest=conn.dest)
            if proc.returncode == 0:
                break
            error = (proc.stderr + proc.stdout).decode(errors="replace").strip()
        else:
            raise RuntimeError(error or "ssh could not cancel the forward")
        with self.lock:
            self.tracked.get(str(conn.pid), {}).pop(str(local), None)
            if info:
                self._set_pin(conn, info["rport"], info["target"], local, False)
            self._save_forwards()
        log(f"{conn.id}: closed forward localhost:{local}")
        self.refresh_forwards()

    def set_pin(self, conn: Conn, local: int, pinned: bool) -> None:
        info = self.tracked.get(str(conn.pid), {}).get(str(local))
        if not info:
            raise RuntimeError("only forwards opened by sshelper can be pinned")
        with self.lock:
            self._set_pin(conn, info["rport"], info["target"], local, pinned)
            self._save_forwards()
        self.refresh_forwards()

    def _set_pin(self, conn: Conn, rport: int, target: str, local: int, pinned: bool) -> None:
        pins = [p for p in self.pins.get(conn.dest, []) if p.get("local") != local]
        if pinned:
            pins.append({"rport": rport, "target": target, "local": local})
        if pins:
            self.pins[conn.dest] = pins
        else:
            self.pins.pop(conn.dest, None)

    def _restore_pins(self, conn: Conn) -> None:
        active = {item["port"] for item in local_listeners() if item["pid"] == conn.pid}
        for pin in list(self.pins.get(conn.dest, [])):
            if pin["local"] in active:
                continue
            try:
                self.open_forward(conn, pin["rport"], pin["target"], pin["local"])
            except (RuntimeError, ValueError, OSError, subprocess.SubprocessError) as exc:
                log(f"{conn.id}: cannot restore pinned forward {pin}: {exc}")

    def refresh_forwards(self) -> None:
        listeners = local_listeners()
        with self.lock:
            for conn in self.conns.values():
                conn.forwards = self._forwards_for(conn, listeners)
                self._mark_detected(conn)
        self.bump()

    # -- push channel -------------------------------------------------------------

    def _setup_push(self, conn: Conn) -> None:
        server = PushServer(("127.0.0.1", 0), PushHandler)
        server.daemon_ref = self
        server.conn = conn
        threading.Thread(target=server.serve_forever, daemon=True).start()
        lport = server.server_address[1]
        try:
            proc = ssh_mux(conn.sock, "-O", "forward", "-R", f"0:127.0.0.1:{lport}",
                           dest=conn.dest)
        except (OSError, subprocess.SubprocessError) as exc:
            proc = None
            conn.push_error = str(exc)
        out = proc.stdout.decode(errors="replace") if proc else ""
        err = proc.stderr.decode(errors="replace") if proc else ""
        match = re.search(r"(\d+)", out) or re.search(r"Allocated port (\d+)", err)
        if proc is None or proc.returncode != 0 or not match:
            server.shutdown()
            server.server_close()
            if proc is not None:
                conn.push_error = (err + out).strip() or "remote forward failed"
                conn.remote_fwd = "blocked"
            log(f"{conn.id}: push channel unavailable: {conn.push_error}")
            return
        conn.remote_fwd = "ok"
        conn.push_server = server
        conn.push_lport = lport
        conn.push_rport = int(match.group(1))
        conn.push_token = secrets.token_hex(16)
        if not self._write_remote_endpoint(conn):
            self._teardown_push(conn)
            return
        conn.push_ready = True
        self.bump()
        log(f"{conn.id}: push channel on remote port {conn.push_rport}")
        self.sync_skill(conn)

    # -- agent skill (Claude Code, Codex, ...) ------------------------------------------------

    def skill_enabled(self, conn: Conn) -> bool:
        hosts = set(self.settings["agent_skill_hosts"])
        return bool(conn.dest and (conn.dest in hosts or conn.id in hosts))

    def sync_skill(self, conn: Conn) -> None:
        """Install the skill on enabled hosts, remove our skill from the others."""
        if conn.status != "ok":
            return
        try:
            if self.skill_enabled(conn) and conn.push_ready:
                dirs = " ".join(f'"{d}"' for d in REMOTE_SKILL_DIRS)
                proc = remote_run(
                    conn.sock, conn.dest,
                    f't=$(mktemp) && cat > "$t" && for d in {dirs}; do '
                    'mkdir -p "$d" && cp "$t" "$d/SKILL.md.tmp" && chmod 644 "$d/SKILL.md.tmp" '
                    '&& mv "$d/SKILL.md.tmp" "$d/SKILL.md" || { rm -f "$t"; exit 1; }; done; rm -f "$t"',
                    input=skill_markdown(self, conn).encode(), timeout=15)
                conn.skill = "installed" if proc.returncode == 0 else (
                    "error: " + (proc.stderr.decode(errors="replace").strip() or "write failed"))
            elif not self.skill_enabled(conn):
                dirs = " ".join(f'"{d}"' for d in REMOTE_SKILL_DIRS)
                proc = remote_run(
                    conn.sock, conn.dest,
                    f'for d in {dirs}; do if grep -q "{SKILL_MARKER}" "$d/SKILL.md" 2>/dev/null; '
                    'then rm -f "$d/SKILL.md" && rmdir "$d" 2>/dev/null; echo removed; fi; done; true',
                    timeout=15)
                conn.skill = "removed" if b"removed" in proc.stdout else ""
        except (OSError, subprocess.SubprocessError) as exc:
            conn.skill = f"error: {exc}"
        log(f"{conn.id}: agent skill {conn.skill or 'off'}")
        self.bump()

    def set_skill(self, conn: Conn, enabled: bool) -> None:
        settings = load_settings()
        hosts = [h for h in settings["agent_skill_hosts"] if h not in (conn.dest, conn.id)]
        if enabled:
            hosts.append(conn.dest or conn.id)
        settings["agent_skill_hosts"] = hosts
        save_settings(settings)
        self.settings["agent_skill_hosts"] = hosts
        self.sync_skill(conn)

    def _write_remote_endpoint(self, conn: Conn) -> bool:
        laptop = re.sub(r"[^A-Za-z0-9._-]", "-", self.laptop)
        url = f"http://127.0.0.1:{conn.push_rport}"
        data = json.dumps({"port": conn.push_rport, "token": conn.push_token,
                           "url": url, "laptop": laptop})
        script = (
            f'umask 077; d="{REMOTE_DIR}/hosts"; mkdir -p "$d" && chmod 700 "{REMOTE_DIR}" '
            '&& f="$d/$(uname -n)" && cat > "$f.json.tmp" && mv "$f.json.tmp" "$f.json" '
            f'&& {{ echo "SSHELPER_PORT={conn.push_rport}"; echo "SSHELPER_TOKEN={conn.push_token}"; '
            f'echo "SSHELPER_URL={url}"; echo "SSHELPER_LAPTOP={laptop}"; }} > "$f.env"'
            '; q="/tmp/sshelper-$(id -u)"; mkdir -p "$q/inbox" 2>/dev/null; '
            '[ -O "$q" ] && [ -O "$q/inbox" ] && chmod 700 "$q" "$q/inbox"; true'
        )
        readme = push_help(self, conn)
        try:
            proc = remote_run(conn.sock, conn.dest, script, input=data.encode(), timeout=15)
            if proc.returncode != 0:
                conn.push_error = proc.stderr.decode(errors="replace").strip() or "cannot write endpoint file"
                return False
            remote_run(conn.sock, conn.dest,
                       f'umask 077; cat > "{REMOTE_DIR}/README.md.tmp" && '
                       f'chmod 644 "{REMOTE_DIR}/README.md.tmp" && '
                       f'mv "{REMOTE_DIR}/README.md.tmp" "{REMOTE_DIR}/README.md" && '
                       f'rm -f "{REMOTE_DIR}/README.txt"',
                       input=readme.encode(), timeout=15)
            remote_run(conn.sock, conn.dest,
                       f'umask 077; cat > "{REMOTE_DIR}/push.tmp" && chmod 700 "{REMOTE_DIR}/push.tmp" '
                       f'&& mv "{REMOTE_DIR}/push.tmp" "{REMOTE_DIR}/push"',
                       input=PUSH_SCRIPT.encode(), timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            conn.push_error = str(exc)
            return False
        conn.push_error = ""
        return True

    def _stop_push_server(self, conn: Conn) -> None:
        server = conn.push_server
        conn.push_server = None
        if server is not None:
            threading.Thread(target=lambda: (server.shutdown(), server.server_close()),
                             daemon=True).start()

    def _teardown_push(self, conn: Conn) -> None:
        rport, lport, token = conn.push_rport, conn.push_lport, conn.push_token
        self._stop_push_server(conn)
        conn.push_ready = False
        conn.push_rport = 0
        if not rport:
            return
        try:
            ssh_mux(conn.sock, "-O", "cancel", "-R", f"{rport}:127.0.0.1:{lport}",
                    dest=conn.dest, timeout=5)
            remote_run(conn.sock, conn.dest,
                       f'f="{REMOTE_DIR}/hosts/$(uname -n)"; '
                       f'grep -q {token} "$f.json" 2>/dev/null && rm -f "$f.json" "$f.env"; true',
                       timeout=5)
        except (OSError, subprocess.SubprocessError):
            pass

    def shutdown(self) -> None:
        self.stop.set()
        self.bump()
        with self.lock:
            conns = list(self.conns.values())
        threads = [threading.Thread(target=self._teardown_push, args=(c,)) for c in conns]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=8)

    # -- pushes -------------------------------------------------------------------

    def add_push(self, conn: Conn, payload: object, via: str = "port") -> dict:
        record = build_push(payload, conn)
        paths = [item["path"] for item in record["items"] if item["type"] == "path"]
        if paths:
            self._stat_into(conn, record)
        with self.lock:
            self.pushes.append(record)
            try:
                ensure_private_dir(self.pushes_file.parent)
                with self.pushes_file.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, sort_keys=True) + "\n")
                os.chmod(self.pushes_file, 0o600)
            except OSError as exc:
                log(f"cannot save push: {exc}")
            if len(self.pushes) > self.settings["retention_count"] * 1.1:
                self.pushes = self._apply_retention(self.pushes)
                self._rewrite_pushes(self.pushes)
        log(f"{conn.id}: push {record['id']} to project {record['project']} (via {via})")
        self.bump()
        return record

    def _stat_into(self, conn: Conn, record: dict) -> None:
        items = [item for item in record["items"] if item["type"] == "path"]
        try:
            proc = remote_run(conn.sock, conn.dest, stat_script([i["path"] for i in items]),
                              timeout=15)
            metas = parse_stat_output(proc.stdout.decode(errors="replace"), len(items))
        except (OSError, subprocess.SubprocessError):
            return
        for item, meta in zip(items, metas):
            item["meta"] = meta

    def restat_push(self, push_id: str) -> None:
        record = next((p for p in self.pushes if p["id"] == push_id), None)
        if record is None:
            raise LookupError("no such push")
        conn = self.find_conn(record["from"]["conn"])
        self._stat_into(conn, record)
        with self.lock:
            self._rewrite_pushes(self.pushes)
        self.bump()

    def delete_pushes(self, push_id: str | None = None, project: str | None = None) -> int:
        with self.lock:
            before = len(self.pushes)
            self.pushes = [p for p in self.pushes
                           if not ((push_id and p["id"] == push_id)
                                   or (project and p["project"] == project))]
            removed = before - len(self.pushes)
            if removed:
                self._rewrite_pushes(self.pushes)
        if removed:
            self.bump()
        return removed

    # -- snapshot -------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self.lock:
            return {
                "version": self.version,
                "scans": self.scans,
                "app_version": __version__,
                "laptop": self.laptop,
                "port": self.port,
                "address": dashboard_url(self.port),
                "notice": self.notice,
                "connections": [c.public() for c in sorted(self.conns.values(), key=lambda c: c.id)],
                "uncontrolled": self.uncontrolled,
                "pins": self.pins,
                "pushes": self.pushes[-500:],
                "settings": {k: self.settings[k] for k in ("port", "browser", "push_channel",
                                                            "push_disabled_hosts",
                                                            "agent_skill_hosts")},
            }


# ---------------------------------------------------------------------------
# push channel (remote-facing): write-only, token protected
# ---------------------------------------------------------------------------


class PushServer(ThreadingHTTPServer):
    daemon_threads = True
    daemon_ref: Daemon
    conn: Conn


PUSH_SCRIPT = r"""#!/bin/sh
# sshelper push helper, written by the sshelper daemon on your laptop.
# Usage: ~/.sshelper/push '<json>'   (or JSON on stdin)   |   ~/.sshelper/push help
case "${1:-}" in -h|--help|help) cat "$HOME/.sshelper/README.md"; exit 0;; esac
if [ $# -gt 0 ]; then data="$1"; else data=$(cat); fi
if [ -z "$data" ]; then
    echo "sshelper: nothing to push (give the JSON as argument or on stdin)" >&2
    exit 1
fi
if command -v python3 >/dev/null 2>&1; then
    err=$(printf '%s' "$data" | python3 -c 'import json, sys; json.load(sys.stdin)' 2>&1) || {
        echo "{\"ok\": false, \"error\": \"invalid JSON: $(printf '%s' "$err" | tail -n 1 | tr '"' "'")\"}"
        exit 1
    }
fi
f="$HOME/.sshelper/hosts/$(uname -n).env"
out=""
rc=7
if [ -r "$f" ]; then
    . "$f"
    export SSHELPER_URL SSHELPER_TOKEN
    if command -v curl >/dev/null 2>&1; then
        out=$(printf '%s' "$data" | curl -sS --noproxy '*' --max-time 30 "$SSHELPER_URL/push" \
            -H "X-Token: $SSHELPER_TOKEN" -H 'Content-Type: application/json' --data-binary @- 2>&1)
        rc=$?
    elif command -v python3 >/dev/null 2>&1; then
        out=$(printf '%s' "$data" | python3 -c '
import os, sys, urllib.request as u, urllib.error as e
req = u.Request(os.environ["SSHELPER_URL"] + "/push", data=sys.stdin.buffer.read(),
                headers={"X-Token": os.environ["SSHELPER_TOKEN"], "Content-Type": "application/json"})
try:
    print(u.build_opener(u.ProxyHandler({})).open(req, timeout=30).read().decode())
except e.HTTPError as x:
    print(x.read().decode())
except OSError as x:
    print(x); sys.exit(7)' 2>&1)
        rc=$?
    fi
fi
if [ $rc -eq 0 ]; then
    printf '%s\n' "$out"
    case "$out" in *'"ok": true'*) exit 0;; *) exit 1;; esac
fi
# The port is not reachable from here (a sandboxed agent without network, or
# the laptop is offline): queue the push as a file; the laptop collects the
# inbox over ssh every few seconds while it is connected.
q="/tmp/sshelper-$(id -u)/inbox"
umask 077
mkdir -p "$q" 2>/dev/null
if [ -d "$q" ] && [ -O "$q" ] && [ -O "${q%/inbox}" ]; then
    n="$q/$(date +%s)-$$"
    if printf '%s' "$data" > "$n.tmp" 2>/dev/null && mv "$n.tmp" "$n.json"; then
        echo '{"ok": true, "queued": true, "note": "laptop port not reachable from here (sandbox or offline): queued, the laptop collects it within seconds while connected"}'
        exit 0
    fi
fi
echo "sshelper: laptop not reachable and cannot queue in $q" >&2
exit 2
"""


# Claude Code reads ~/.claude/skills; Codex and other agents following the
# shared Agent Skills layout read ~/.agents/skills. (Not ~/.codex/skills too:
# Codex reads both and would list the skill twice.)
REMOTE_SKILL_DIRS = ["$HOME/.claude/skills/sshelper", "$HOME/.agents/skills/sshelper"]
SKILL_MARKER = "managed by sshelper"


def skill_markdown(daemon: Daemon, conn: Conn) -> str:
    body = push_help(daemon, conn).split("\n", 1)[1]  # drop the "# ..." title line
    return f"""---
name: sshelper
description: Show results to the user on their laptop. Use whenever you produce something the user should look at (videos, images, plots, log files, result folders, or a web UI/server running on a port such as viser, tensorboard or gradio) instead of only printing file paths. Pushes them to the user's sshelper dashboard through the existing ssh connection.
---

<!-- {SKILL_MARKER} on the laptop "{daemon.laptop}"; rewritten on every connect.
     Turn off on the laptop with: sshelper agent off {conn.dest or conn.id} -->

# sshelper: show results on the user's laptop
{body}"""


def push_help(daemon: Daemon, conn: Conn) -> str:
    dash = dashboard_url(daemon.port).rstrip("/")
    return f"""# sshelper: show results on the laptop

The laptop "{daemon.laptop}" is connected to this machine ({conn.rhost}) over
ssh and runs sshelper. Whatever you push shows up there as a box in the
browser at {dash}/<project>. Only paths are sent: files stay on this machine
and are streamed over ssh when someone opens them. Nothing is sent back here.

## Push

    ~/.sshelper/push '{{"project": "<project>", "title": "<what this is>", "items": [ ... ]}}'

(or pipe the JSON on stdin). Full example:

    ~/.sshelper/push '{{
      "project": "<project>",
      "title":   "run 12: pick cube, seed 3",
      "sender":  "claude-agent",
      "items": [
        {{"path": "/abs/path/run12/cam0.mp4", "caption": "wrist cam"}},
        {{"path": "/abs/path/run12/"}},
        {{"port": 8080, "name": "viser scene"}},
        {{"text": "success rate 7/10"}},
        {{"url": "https://example.com/report"}}
      ]}}'

Prints {{"ok": true, "id": "...", "url": "..."}} or {{"ok": false, "error": "..."}}.
Works inside sandboxes without network access (e.g. Codex): if the laptop's
port cannot be reached, the push is queued in /tmp/sshelper-<uid>/inbox and
the laptop collects it within seconds while connected; the output then says
"queued": true. Do not ask for network permissions for this.
Exit code 1 = rejected (see error), 2 = could not deliver or queue: then just
tell the user the paths.

## Fields

- project (required): choose it yourself - the repo, experiment or task
  name. Lowercase letters, digits, "-" and "_". Each project has its own page;
  reuse the same name for related results.
- title: one line saying what this result is.
- sender: who is pushing, e.g. "claude-agent" or "train.py".
- items (1-100), each one of:
  - {{"path": "/absolute/path"}} - a file or folder ("~/" works too). Videos,
    images and audio play inline, folders become a browsable listing, text
    files can be followed live.
  - {{"port": 8080}} - a web UI running on this machine; the laptop can forward
    and open it. Add "host" if it does not listen on localhost.
  - {{"text": "..."}} - a short note or metric.
  - {{"url": "https://..."}} - a link.
  Any item can have a "caption".

## Rules

- One push = one box: group everything that belongs to one run.
- Push only after files are completely written.
- Videos must be browser-playable: H.264 mp4 (OpenCV fourcc "avc1") or webm.
  OpenCV "mp4v" does NOT play in browsers. Re-encode with
  ffmpeg -i in.mp4 -c:v libx264 -pix_fmt yuv420p out.mp4
- At most 64 KB of JSON per push.

## Raw HTTP (if you cannot use ~/.sshelper/push)

Port and token are in ~/.sshelper/hosts/$(uname -n).env (also .json). They
change whenever the laptop reconnects, so read them right before pushing.

    . ~/.sshelper/hosts/$(uname -n).env
    curl -s --noproxy '*' "$SSHELPER_URL/push" -H "X-Token: $SSHELPER_TOKEN" \\
      -H 'Content-Type: application/json' -d '{{"project": "<project>", "items": [...]}}'
    curl -s --noproxy '*' "$SSHELPER_URL/push?project=<project>&path=/abs/file.mp4&token=$SSHELPER_TOKEN"
    curl -s --noproxy '*' "$SSHELPER_URL/ping" -H "X-Token: $SSHELPER_TOKEN"
"""


class PushHandler(BaseHTTPRequestHandler):
    server: PushServer
    server_version = "sshelper"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def _send(self, code: int, body: str | dict, ctype: str = "application/json") -> None:
        data = (json.dumps(body) + "\n" if isinstance(body, dict) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self, query: dict) -> bool:
        token = self.headers.get("X-Token") or (query.get("token") or [""])[0]
        expected = self.server.conn.push_token
        return bool(expected) and hmac.compare_digest(token.encode(), expected.encode())

    def _push(self, payload: object) -> None:
        try:
            record = self.server.daemon_ref.add_push(self.server.conn, payload)
        except ValueError as exc:
            self._send(400, {"ok": False, "error": str(exc)})
            return
        url = dashboard_url(self.server.daemon_ref.port, f"/{record['project']}#p-{record['id']}")
        self._send(200, {"ok": True, "id": record["id"], "url": url})

    def do_GET(self) -> None:  # noqa: N802
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query)
        if parts.path in ("/", "/help"):
            self._send(200, push_help(self.server.daemon_ref, self.server.conn), "text/plain")
            return
        if parts.path not in ("/ping", "/push"):
            self._send(404, {"ok": False, "error": "unknown endpoint; GET / for instructions"})
            return
        if not self._authorized(query):
            self._send(401, {"ok": False, "error": "missing or wrong token; GET / for instructions"})
            return
        if parts.path == "/ping":
            daemon = self.server.daemon_ref
            self._send(200, {"ok": True, "laptop": daemon.laptop,
                             "dashboard": dashboard_url(daemon.port)})
            return
        first = {k: v[0] for k, v in query.items() if v}
        item = {k: first[k] for k in ("path", "port", "text", "url", "caption", "host") if k in first}
        payload = {k: first[k] for k in ("project", "title", "sender") if k in first}
        payload["items"] = [item] if item else []
        self._push(payload)

    def do_POST(self) -> None:  # noqa: N802
        parts = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parts.query)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > PUSH_BODY_LIMIT:
            self._send(413, {"ok": False, "error": "body too large (max 64 KB)"})
            self.close_connection = True
            return
        body = self.rfile.read(length)
        if parts.path != "/push":
            self._send(404, {"ok": False, "error": "unknown endpoint; GET / for instructions"})
            return
        if not self._authorized(query):
            self._send(401, {"ok": False, "error": "missing or wrong token; GET / for instructions"})
            return
        try:
            payload = json.loads(body.decode("utf-8") or "null")
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._send(400, {"ok": False, "error": f"invalid JSON: {exc}"})
            return
        self._push(payload)


# ---------------------------------------------------------------------------
# dashboard + local API (laptop-facing)
# ---------------------------------------------------------------------------

ALLOWED_HOSTS = {DASHBOARD_HOST, "localhost", "127.0.0.1", "[::1]"}
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="7" fill="#2f6fde"/>'
    '<path d="M8 11l6 5-6 5M16 22h8" stroke="#fff" stroke-width="2.6" fill="none" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)
FILE_CSP = "sandbox allow-scripts allow-popups allow-forms allow-downloads"
APP_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; media-src 'self'; connect-src 'self'; frame-ancestors 'none'"
)
LISTING_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"


def stop_remote(proc: subprocess.Popen) -> None:
    """Close stdin (ends the remote command), then make sure ssh is gone."""
    try:
        if proc.stdin and not proc.stdin.closed:
            proc.stdin.close()
    except OSError:
        pass
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    daemon_ref: Daemon


def file_url(conn_id: str, path: str, meta: dict | None = None) -> str:
    url = f"/f/{urllib.parse.quote(conn_id)}{urllib.parse.quote(path)}"
    if meta and meta.get("kind") == "file":
        url += f"?v={meta.get('mtime', 0)}-{meta.get('size', 0)}"
    return url


def page(title: str, body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title><link rel="icon" href="/favicon.svg">
<style>
:root {{ --bg:#f7f7f8; --fg:#1c1d21; --muted:#6b6f7a; --line:#e3e4e8; --card:#fff; --accent:#2f6fde; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#16171a; --fg:#e8e9ec; --muted:#9a9eaa; --line:#2c2e34; --card:#1e2024; --accent:#6b9cff; }} }}
body {{ margin:0; background:var(--bg); color:var(--fg); font:14px/1.5 system-ui,sans-serif; }}
main {{ max-width:960px; margin:0 auto; padding:24px 16px; }}
a {{ color:var(--accent); text-decoration:none; }} a:hover {{ text-decoration:underline; }}
h1 {{ font-size:16px; font-weight:600; word-break:break-all; }}
table {{ width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; }}
td {{ padding:6px 10px; border-top:1px solid var(--line); vertical-align:top; }}
tr:first-child td {{ border-top:0; }}
.muted {{ color:var(--muted); }} .num {{ text-align:right; white-space:nowrap; font-variant-numeric:tabular-nums; }}
.name {{ word-break:break-all; }}
</style></head><body><main>{body}</main></body></html>"""


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer
    server_version = "sshelper"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    # -- helpers ------------------------------------------------------------------

    @property
    def daemon(self) -> Daemon:
        return self.server.daemon_ref

    def _bytes(self, code: int, data: bytes, ctype: str, headers: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _json(self, code: int, body: dict) -> None:
        self._bytes(code, (json.dumps(body) + "\n").encode(), "application/json",
                    {"Cache-Control": "no-store"})

    def _html(self, code: int, text: str, csp: str = LISTING_CSP) -> None:
        self._bytes(code, text.encode(), "text/html; charset=utf-8",
                    {"Cache-Control": "no-store", "Content-Security-Policy": csp,
                     "X-Content-Type-Options": "nosniff"})

    def _error_page(self, code: int, message: str) -> None:
        body = f'<h1>{html.escape(message)}</h1><p><a href="/">back to sshelper</a></p>'
        self._html(code, page("sshelper", body))

    def _guard(self, mutating: bool = False) -> bool:
        host = (self.headers.get("Host") or "").lower()
        name = host.split("]")[0] + "]" if host.startswith("[") else host.rsplit(":", 1)[0]
        if name not in ALLOWED_HOSTS:
            self._bytes(421, b"wrong host\n", "text/plain")
            return False
        if self.headers.get("Sec-Fetch-Site", "none") not in ("same-origin", "none"):
            self._bytes(403, b"cross-site request refused\n", "text/plain")
            return False
        if mutating:
            token = self.headers.get("X-Session", "")
            if not hmac.compare_digest(token.encode(), self.daemon.session.encode()):
                self._json(403, {"ok": False, "error": "bad session token; reload the page"})
                return False
            origin = self.headers.get("Origin")
            if origin and urllib.parse.urlsplit(origin).hostname not in ALLOWED_HOSTS:
                self._json(403, {"ok": False, "error": "bad origin"})
                return False
        return True

    # -- GET ----------------------------------------------------------------------

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_GET(self) -> None:  # noqa: N802
        if not self._guard():
            return
        parts = urllib.parse.urlsplit(self.path)
        path = parts.path
        query = urllib.parse.parse_qs(parts.query)
        try:
            if path == "/api/ping":
                self._json(200, {"ok": True, "version": __version__, "pid": os.getpid(),
                                 "port": self.daemon.port})
            elif path == "/api/state":
                self._json(200, self.daemon.snapshot())
            elif path == "/api/events":
                self._events()
            elif path in ("/favicon.svg", "/favicon.ico"):
                self._bytes(200, FAVICON_SVG.encode(), "image/svg+xml",
                            {"Cache-Control": "max-age=86400"})
            elif path.startswith("/f/"):
                self._file(path[3:], query)
            elif path == "/" or re.fullmatch(r"/[a-z0-9][a-z0-9_-]{0,62}/?", path):
                text = APP_HTML.replace("__SESSION__", self.daemon.session)
                self._html(200, text, APP_CSP)
            else:
                self._error_page(404, "not found")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _events(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        version = -1
        while not self.daemon.stop.is_set():
            new = self.daemon.wait_change(version, 15)
            chunk = f"data: {new}\n\n" if new != version else ": ping\n\n"
            version = new
            try:
                self.wfile.write(chunk.encode())
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                return

    def _file(self, rest: str, query: dict) -> None:
        conn_id, _, raw_path = rest.partition("/")
        rpath = "/" + urllib.parse.unquote(raw_path)
        try:
            conn = self.daemon.find_conn(urllib.parse.unquote(conn_id))
        except LookupError:
            self._error_page(503, f"{conn_id} is not connected right now")
            return
        try:
            proc = remote_run(conn.sock, conn.dest, stat_script([rpath]), timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            self._error_page(502, f"ssh failed: {exc}")
            return
        meta = parse_stat_output(proc.stdout.decode(errors="replace"), 1)[0]
        if meta["kind"] == "missing":
            self._error_page(404, f"{rpath} does not exist on {conn.id}")
        elif meta["kind"] == "dir":
            if not rpath.endswith("/"):
                self.send_response(301)
                self.send_header("Location", file_url(conn.id, rpath + "/"))
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._listing(conn, rpath)
        elif meta["kind"] != "file":
            self._error_page(415, f"{rpath} is not a regular file")
        elif query.get("follow"):
            self._follow(conn, rpath)
        else:
            self._stream(conn, rpath, meta, query)

    def _listing(self, conn: Conn, rpath: str) -> None:
        quoted = shlex.quote(rpath)
        script = (f'find {quoted} -mindepth 1 -maxdepth 1 -printf "%y\\t%s\\t%T@\\t%f\\n" '
                  f'2>/dev/null || {{ echo "#ls"; ls -1Ap {quoted}; }}')
        try:
            out = remote_run(conn.sock, conn.dest, script, timeout=30).stdout
        except (OSError, subprocess.SubprocessError) as exc:
            self._error_page(502, f"ssh failed: {exc}")
            return
        lines = out.decode(errors="replace").splitlines()
        entries = []
        if lines and lines[0] == "#ls":
            for name in lines[1:]:
                is_dir = name.endswith("/")
                entries.append({"name": name.rstrip("/"), "dir": is_dir, "size": None, "mtime": None})
        else:
            for line in lines:
                bits = line.split("\t", 3)
                if len(bits) != 4:
                    continue
                kind, size, mtime, name = bits
                is_dir = kind == "d"
                try:
                    entries.append({"name": name, "dir": is_dir, "size": int(size),
                                    "mtime": int(float(mtime))})
                except ValueError:
                    continue
        entries.sort(key=lambda e: (not e["dir"], e["name"].lower()))
        crumbs = [f'<a href="/">sshelper</a> / <a href="{file_url(conn.id, "/")}">{html.escape(conn.id)}</a>:']
        acc = ""
        for piece in [p for p in rpath.split("/") if p]:
            acc += "/" + piece
            crumbs.append(f'/<a href="{file_url(conn.id, acc + "/")}">{html.escape(piece)}</a>')
        rows = []
        if rpath != "/":
            parent = rpath.rstrip("/").rsplit("/", 1)[0] + "/"
            rows.append(f'<tr><td class="name"><a href="{file_url(conn.id, parent)}">..</a></td>'
                        '<td></td><td></td><td></td></tr>')
        for entry in entries:
            full = rpath + entry["name"] + ("/" if entry["dir"] else "")
            meta = None if entry["dir"] or entry["size"] is None else {
                "kind": "file", "size": entry["size"], "mtime": entry["mtime"]}
            href = file_url(conn.id, full, meta)
            label = html.escape(entry["name"]) + ("/" if entry["dir"] else "")
            size = "" if entry["dir"] or entry["size"] is None else human_size(entry["size"])
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry["mtime"])) if entry["mtime"] else ""
            extra = ""
            if not entry["dir"] and guess_mime(entry["name"]).startswith("text/plain"):
                extra = f'<a href="{file_url(conn.id, full)}?follow=1">follow</a>'
            rows.append(f'<tr><td class="name"><a href="{href}">{label}</a></td>'
                        f'<td class="num muted">{size}</td><td class="num muted">{when}</td>'
                        f'<td class="num">{extra}</td></tr>')
        body = (f'<h1>{"".join(crumbs)}</h1>'
                f'<p class="muted">{len(entries)} entries on {html.escape(conn.rhost or conn.dest)}</p>'
                f'<table>{"".join(rows)}</table>')
        self._html(200, page(f"{conn.id}:{rpath}", body))

    def _stream(self, conn: Conn, rpath: str, meta: dict, query: dict) -> None:
        size, mtime = meta["size"], meta["mtime"]
        etag = f'"{mtime}-{size}"'
        immutable = (query.get("v") or [""])[0] == f"{mtime}-{size}"
        headers = {
            "Accept-Ranges": "bytes",
            "ETag": etag,
            "Last-Modified": time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(mtime)),
            "Cache-Control": "private, max-age=31536000, immutable" if immutable else "private, no-cache",
            "Content-Security-Policy": FILE_CSP,
            "X-Content-Type-Options": "nosniff",
        }
        if query.get("download"):
            name = os.path.basename(rpath).replace('"', "")
            headers["Content-Disposition"] = f'attachment; filename="{name}"'
        if self.headers.get("If-None-Match") == etag:
            self.send_response(304)
            for key in ("ETag", "Cache-Control"):
                self.send_header(key, headers[key])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        start, end, code = 0, size - 1, 200
        match = re.fullmatch(r"bytes=(\d*)-(\d*)", (self.headers.get("Range") or "").strip())
        if match and size > 0 and (match.group(1) or match.group(2)):
            if match.group(1):
                start = int(match.group(1))
                end = min(int(match.group(2)), size - 1) if match.group(2) else size - 1
            else:
                start = max(0, size - int(match.group(2)))
            if start > end or start >= size:
                self.send_response(416)
                self.send_header("Content-Range", f"bytes */{size}")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            code = 206
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
        length = max(0, end - start + 1)
        self.send_response(code)
        self.send_header("Content-Type", guess_mime(rpath))
        self.send_header("Content-Length", str(length))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command == "HEAD" or length == 0:
            return
        quoted = shlex.quote(rpath)
        if start == 0 and length == size:
            script = f"cat -- {quoted}"
        else:
            script = f"tail -c +{start + 1} -- {quoted} | head -c {length}"
        proc = remote_popen(conn.sock, conn.dest, script)
        sent = 0
        try:
            assert proc.stdout is not None
            while sent < length:
                chunk = proc.stdout.read1(256 * 1024)
                if not chunk:
                    break
                chunk = chunk[: length - sent]
                self.wfile.write(chunk)
                sent += len(chunk)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
        if sent < length:
            self.close_connection = True

    def _follow(self, conn: Conn, rpath: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", FILE_CSP)
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        # The remote tail is killed as soon as our stdin closes (cat sees EOF), and
        # our stdin is closed as soon as the browser goes away (watcher below).
        script = (f"tail -n 500 -F -- {shlex.quote(rpath)} 2>&1 & t=$!; "
                  "cat >/dev/null; kill $t 2>/dev/null")
        proc = remote_popen(conn.sock, conn.dest, script, stdin_pipe=True)
        client = self.connection

        def watch_client() -> None:
            try:
                while proc.poll() is None:
                    ready, _, _ = select.select([client], [], [], 1.0)
                    if ready and not client.recv(1, socket.MSG_PEEK):
                        break
            except OSError:
                pass
            stop_remote(proc)

        threading.Thread(target=watch_client, daemon=True).start()
        try:
            assert proc.stdout is not None
            while True:
                chunk = proc.stdout.read1(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            stop_remote(proc)

    # -- POST (local API) -------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        if not self._guard(mutating=True):
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if length < 0 or length > PUSH_BODY_LIMIT:
            self._json(413, {"ok": False, "error": "body too large"})
            self.close_connection = True
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
            result = self._action(urllib.parse.urlsplit(self.path).path, body)
        except (ValueError, LookupError, RuntimeError, OSError,
                subprocess.SubprocessError, json.JSONDecodeError) as exc:
            self._json(400, {"ok": False, "error": str(exc)})
            return
        self._json(200, {"ok": True, **result})

    def _action(self, path: str, body: dict) -> dict:
        daemon = self.daemon

        def conn() -> Conn:
            return daemon.find_conn(str(body.get("conn") or ""))

        def opt_int(key: str) -> int | None:
            value = body.get(key)
            if value in (None, ""):
                return None
            return int(value)

        if path == "/api/forward":
            target = str(body.get("target") or "localhost")
            rport = opt_int("port")
            if rport is None:
                raise ValueError("port is required")
            local = daemon.open_forward(conn(), rport, target, opt_int("local"),
                                        bool(body.get("pin")))
            return {"local": local, "url": f"http://localhost:{local}/"}
        if path == "/api/close":
            local = opt_int("local")
            if local is None:
                raise ValueError("local is required")
            daemon.close_forward(conn(), local)
            return {}
        if path == "/api/pin":
            local = opt_int("local")
            if local is None:
                raise ValueError("local is required")
            daemon.set_pin(conn(), local, bool(body.get("pinned")))
            return {}
        if path == "/api/detect":
            target = conn()
            daemon._detect(target)
            daemon.bump()
            return {"detected": target.detected}
        if path == "/api/push/delete":
            return {"removed": daemon.delete_pushes(push_id=str(body.get("id") or ""))}
        if path == "/api/project/delete":
            return {"removed": daemon.delete_pushes(project=str(body.get("project") or ""))}
        if path == "/api/push/restat":
            daemon.restat_push(str(body.get("id") or ""))
            return {}
        if path == "/api/agent":
            target = conn()
            daemon.set_skill(target, bool(body.get("enabled")))
            return {"skill": target.skill}
        if path == "/api/settings":
            return self._settings(body)
        raise LookupError(f"unknown action {path}")

    def _settings(self, body: dict) -> dict:
        daemon = self.daemon
        settings = load_settings()
        restart = False
        if "port" in body:
            port = int(body["port"])
            if not 1 <= port <= 65535:
                raise ValueError("port must be 1-65535")
            restart = port != daemon.port
            settings["port"] = port
        if "browser" in body:
            settings["browser"] = str(body["browser"])
        if "push_channel" in body:
            settings["push_channel"] = bool(body["push_channel"])
        save_settings(settings)
        for key in ("browser", "push_channel"):
            daemon.settings[key] = settings[key]
        daemon.settings["port"] = settings["port"]
        if restart:
            daemon.notice = (f"Dashboard port set to {settings['port']}; "
                             "run `sshelper daemon restart` to apply.")
        daemon.bump()
        return {"restart": restart}


def run_daemon() -> int:
    ensure_private_dir(state_dir())
    lock_handle = (state_dir() / "daemon.lock").open("w")
    try:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("sshelper: daemon already running", file=sys.stderr)
        return 1
    settings = load_settings()
    daemon = Daemon(settings)
    server = None
    for port in dict.fromkeys([settings["port"], DEFAULT_PORT]):
        try:
            server = DashboardServer(("127.0.0.1", port), DashboardHandler)
            break
        except OSError as exc:
            log(f"cannot listen on 127.0.0.1:{port}: {exc}")
    if server is None:
        try:
            server = DashboardServer(("127.0.0.1", 0), DashboardHandler)
        except OSError as exc:
            log(f"cannot start dashboard: {exc}")
            return 1
    server.daemon_ref = daemon
    daemon.port = server.server_address[1]
    if daemon.port != settings["port"]:
        daemon.notice = (f"Port {settings['port']} was not available; using {daemon.port}. "
                         "See `sshelper doctor`.")
    write_json_atomic(state_dir() / "daemon.json", {
        "pid": os.getpid(), "port": daemon.port, "session": daemon.session,
        "version": __version__, "started": time.time()})
    log(f"sshelper {__version__} daemon on {dashboard_url(daemon.port)} (pid {os.getpid()})")

    def handle_signal(signum: int, frame: object) -> None:
        daemon.stop.set()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    scanner = threading.Thread(target=daemon.scan_loop, daemon=True)
    scanner.start()
    try:
        while not daemon.stop.wait(1):
            pass
    finally:
        log("shutting down")
        daemon.shutdown()
        server.shutdown()
        server.server_close()
        info = read_json(state_dir() / "daemon.json", {})
        if isinstance(info, dict) and info.get("pid") == os.getpid():
            try:
                (state_dir() / "daemon.json").unlink()
            except OSError:
                pass
    return 0


APP_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>sshelper</title>
<link rel="icon" href="/favicon.svg">
<style>
:root {
  --bg: #f6f7f9; --fg: #1b1d22; --muted: #697080; --faint: #9aa0ad; --line: #e2e5ea;
  --card: #ffffff; --chip: #eef0f4; --accent: #2f6fde; --accent-fg: #ffffff;
  --ok: #1f9d55; --warn: #c27c0e; --bad: #d64545; --shadow: 0 1px 2px rgba(0,0,0,.04);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #131417; --fg: #e7e9ee; --muted: #9ba1ae; --faint: #6c7280; --line: #2a2d34;
    --card: #1b1d22; --chip: #262930; --accent: #6b9cff; --accent-fg: #0d1220;
    --ok: #3ccf7e; --warn: #e3a33b; --bad: #ff6b6b; --shadow: none;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--fg);
  font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 12.5px; }
header { position: sticky; top: 0; z-index: 5; background: var(--bg);
  border-bottom: 1px solid var(--line); }
.bar { max-width: 1180px; margin: 0 auto; padding: 10px 16px; display: flex; gap: 12px;
  align-items: center; flex-wrap: wrap; }
.brand { font-weight: 650; font-size: 15px; color: var(--fg); display: flex; align-items: center; gap: 8px; }
.brand img { width: 20px; height: 20px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--faint); display: inline-block; }
.dot.ok { background: var(--ok); } .dot.bad { background: var(--bad); } .dot.warn { background: var(--warn); }
.spacer { flex: 1; }
main { max-width: 1180px; margin: 0 auto; padding: 16px; }
h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted);
  margin: 22px 0 10px; font-weight: 600; }
.notice { background: var(--chip); border: 1px solid var(--line); border-radius: 8px;
  padding: 8px 12px; margin-bottom: 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 12px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 10px;
  padding: 12px 14px; box-shadow: var(--shadow); min-width: 0; }
.card-head { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.card-title { font-weight: 650; font-size: 15px; word-break: break-all; }
.sub { color: var(--muted); font-size: 12.5px; word-break: break-all; }
.badges { display: flex; gap: 6px; flex-wrap: wrap; margin: 8px 0 4px; }
.badge { font-size: 11.5px; padding: 1px 8px; border-radius: 999px; background: var(--chip);
  color: var(--muted); white-space: nowrap; }
.badge.ok { color: var(--ok); } .badge.bad { color: var(--bad); } .badge.warn { color: var(--warn); }
.rows { margin-top: 8px; }
.rows-title { font-size: 11.5px; color: var(--faint); text-transform: uppercase; letter-spacing: .05em;
  margin: 10px 0 4px; }
.row { display: flex; align-items: center; gap: 8px; padding: 4px 0; border-top: 1px solid var(--line);
  min-width: 0; }
.row:first-of-type { border-top: 0; }
.row .grow { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.empty { color: var(--faint); font-size: 12.5px; padding: 4px 0; }
button, .btn { font: inherit; font-size: 12.5px; border: 1px solid var(--line); background: var(--card);
  color: var(--fg); border-radius: 6px; padding: 2px 9px; cursor: pointer; white-space: nowrap; }
button:hover, .btn:hover { border-color: var(--accent); text-decoration: none; }
button.primary { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
button.icon { padding: 2px 7px; color: var(--muted); }
button.on { color: var(--accent); border-color: var(--accent); }
input { font: inherit; font-size: 12.5px; border: 1px solid var(--line); background: var(--bg);
  color: var(--fg); border-radius: 6px; padding: 3px 8px; min-width: 0; }
input:focus { outline: 2px solid color-mix(in srgb, var(--accent) 40%, transparent); border-color: var(--accent); }
.addform { display: flex; gap: 6px; margin-top: 10px; }
.addform input.target { flex: 1; } .addform input.local { width: 84px; }
.chips { display: flex; gap: 6px; flex-wrap: wrap; margin-bottom: 12px; }
.chip { font-size: 12.5px; padding: 3px 10px; border-radius: 999px; background: var(--chip);
  color: var(--fg); border: 1px solid transparent; cursor: pointer; }
.chip.active { border-color: var(--accent); color: var(--accent); }
.chip .n { color: var(--faint); margin-left: 4px; }
.boxes { display: grid; gap: 12px; }
.box-head { display: flex; gap: 8px; align-items: baseline; flex-wrap: wrap; }
.box-project { font-weight: 650; }
.box-title { font-weight: 500; word-break: break-word; }
.box-time { color: var(--muted); font-size: 12.5px; margin-left: auto; white-space: nowrap; }
.box-from { color: var(--muted); font-size: 12.5px; margin: 2px 0 10px; word-break: break-all; }
.box-from .via { color: var(--faint); font-style: italic; }
.media { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 10px; }
.media figure { margin: 0; min-width: 0; }
.media video, .media img { width: 100%; max-height: 420px; background: #000; border-radius: 6px; display: block;
  object-fit: contain; }
.media img { background: var(--chip); }
figcaption { font-size: 12.5px; color: var(--muted); margin-top: 4px; word-break: break-all; }
.items { margin-top: 8px; display: grid; gap: 4px; }
.item { display: flex; gap: 8px; align-items: center; min-width: 0; flex-wrap: wrap; }
.item .path { word-break: break-all; }
.text { white-space: pre-wrap; background: var(--chip); border-radius: 6px; padding: 6px 10px; margin: 0;
  font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; word-break: break-word; }
.warnline { color: var(--warn); font-size: 12.5px; }
.toast { position: fixed; bottom: 16px; left: 50%; transform: translateX(-50%); background: var(--fg);
  color: var(--bg); padding: 8px 14px; border-radius: 8px; max-width: calc(100% - 32px); z-index: 10;
  opacity: 0; transition: opacity .2s; pointer-events: none; }
.toast.show { opacity: 1; }
details.settings { margin-top: 28px; }
details.settings summary { cursor: pointer; color: var(--muted); }
.settings-grid { display: grid; grid-template-columns: max-content 1fr; gap: 8px 12px; align-items: center;
  margin-top: 10px; max-width: 520px; }
.back { margin-right: 4px; }
@media (max-width: 560px) {
  .grid { grid-template-columns: 1fr; } .media { grid-template-columns: 1fr; }
  .box-time { margin-left: 0; }
}
</style>
</head>
<body>
<header><div class="bar">
  <a class="brand" href="/"><img src="/favicon.svg" alt="">sshelper</a>
  <span class="sub" id="laptop"></span>
  <span class="spacer"></span>
  <span class="sub" id="live"><span class="dot" id="livedot"></span> <span id="livetext">connecting</span></span>
</div></header>
<main>
  <div id="notice"></div>
  <section id="conn-section">
    <h2>Connections</h2>
    <div class="grid" id="conns"></div>
    <div id="uncontrolled"></div>
  </section>
  <section>
    <h2 id="pushes-title">Projects</h2>
    <div class="chips" id="chips"></div>
    <div class="boxes" id="boxes"></div>
  </section>
  <details class="settings" id="settings">
    <summary>Settings</summary>
    <div class="settings-grid">
      <label for="set-port">Dashboard port</label>
      <span><input id="set-port" data-keep="set-port" type="number" min="1" max="65535" style="width:100px">
        <span class="sub">80 = http://ssh.localhost (needs <code>sshelper setup --port 80</code> once)</span></span>
      <label for="set-browser">Browser command</label>
      <input id="set-browser" data-keep="set-browser" placeholder="default browser">
      <label for="set-push">Push channel</label>
      <span><input id="set-push" type="checkbox"> <span class="sub">open a push port on every connection</span></span>
      <span></span><span><button class="primary" id="set-save">Save</button></span>
    </div>
  </details>
</main>
<div class="toast" id="toast"></div>
<script>
"use strict";
const SESSION = "__SESSION__";
let state = null;
let filterHost = "";
const boxEls = new Map();
let lastConnKey = "", lastChipKey = "", lastPushKey = "";

function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

function toast(msg) {
  const t = document.getElementById("toast");
  t.textContent = msg; t.classList.add("show");
  clearTimeout(toast.timer); toast.timer = setTimeout(() => t.classList.remove("show"), 3500);
}

async function api(action, body) {
  try {
    const r = await fetch("/api/" + action, {method: "POST",
      headers: {"Content-Type": "application/json", "X-Session": SESSION},
      body: JSON.stringify(body || {})});
    const j = await r.json();
    if (!j.ok) toast(j.error || "failed");
    return j;
  } catch (e) { toast("daemon not reachable"); return {ok: false}; }
}

function project() {
  const p = decodeURIComponent(location.pathname).replace(/^\/|\/$/g, "");
  return p || "";
}

function rel(ts) {
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return "just now";
  if (s < 3600) return Math.floor(s / 60) + " min ago";
  if (s < 86400) return Math.floor(s / 3600) + " h ago";
  return new Date(ts * 1000).toLocaleDateString();
}

function size(n) {
  if (n === undefined || n === null) return "";
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i ? v.toFixed(1) : v) + " " + u[i];
}

function encPath(p) { return p.split("/").map(encodeURIComponent).join("/"); }
function fileUrl(conn, path, meta) {
  let u = "/f/" + encodeURIComponent(conn) + encPath(path);
  if (meta && meta.kind === "file") u += "?v=" + meta.mtime + "-" + meta.size;
  return u;
}

const EXT = {
  video: ["mp4", "webm", "mov", "m4v", "ogv", "mkv"],
  image: ["png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "avif"],
  audio: ["mp3", "wav", "ogg", "flac", "m4a", "opus"],
  text: ["txt", "log", "out", "err", "md", "json", "yaml", "yml", "csv", "tsv", "py", "sh", "toml", "cfg", "ini", "conf"],
};
function kindOf(path) {
  const ext = (path.split(".").pop() || "").toLowerCase();
  for (const [k, list] of Object.entries(EXT)) if (list.includes(ext)) return k;
  return "file";
}

function connById(id) { return (state.connections || []).find(c => c.id === id); }

// ---------------------------------------------------------------- connections

function statusBadges(c) {
  const out = [];
  if (c.status === "connecting") out.push(h("span", {class: "badge"}, "connecting…"));
  if (c.status === "noshell") out.push(h("span", {class: "badge warn", title: c.error}, "no shell"));
  if (c.local_fwd === "blocked") out.push(h("span", {class: "badge bad"}, "port forwarding blocked by server"));
  if (c.push.ok) out.push(h("span", {class: "badge ok", title: "agents on " + (c.rhost || c.dest) +
      " can push to remote port " + c.push.port}, "push :" + c.push.port));
  else if (c.remote_fwd === "blocked") out.push(h("span", {class: "badge bad", title: c.push.error}, "reverse forwarding blocked"));
  else if (c.push.error) out.push(h("span", {class: "badge warn", title: c.push.error}, "push unavailable"));
  return out;
}

function forwardRow(c, f) {
  const target = f.external ? "opened outside sshelper" : (f.target + ":" + f.rport);
  return h("div", {class: "row"},
    h("a", {href: "http://localhost:" + f.local + "/", target: "_blank", class: "mono"}, "localhost:" + f.local),
    h("span", {class: "grow sub mono"}, "→ " + target),
    f.external ? null : h("button", {class: "icon" + (f.pinned ? " on" : ""), title: f.pinned ?
      "pinned: reopened when " + c.dest + " reconnects" : "pin: reopen on reconnect",
      onclick: () => api("pin", {conn: c.id, local: f.local, pinned: !f.pinned})}, f.pinned ? "pinned" : "pin"),
    h("button", {class: "icon", title: "close forward", onclick: () => api("close", {conn: c.id, local: f.local})}, "✕"));
}

function detectedRow(c, d) {
  const label = d.target === "localhost" ? String(d.port) : d.target + ":" + d.port;
  return h("div", {class: "row"},
    h("span", {class: "mono"}, label),
    h("span", {class: "grow sub", title: d.name}, d.name),
    d.forwarded_local
      ? h("a", {class: "btn", href: "http://localhost:" + d.forwarded_local + "/", target: "_blank"}, "open")
      : h("button", {onclick: async (ev) => {
          ev.target.disabled = true;
          const r = await api("forward", {conn: c.id, port: d.port, target: d.target});
          if (r.ok) toast("forwarded to localhost:" + r.local);
          ev.target.disabled = false;
        }}, "forward"));
}

function addForm(c) {
  const target = h("input", {class: "target mono", placeholder: "port, port:local, host:port", "data-keep": "t-" + c.id});
  const local = h("input", {class: "local mono", placeholder: "local", "data-keep": "l-" + c.id, inputmode: "numeric"});
  const go = async () => {
    const raw = target.value.trim();
    // PORT | PORT:LOCAL | HOST:PORT | HOST:PORT:LOCAL  (same rules as the CLI)
    const p = raw.split(":"), num = x => /^\d+$/.test(x);
    let host = "localhost", port = null, loc = local.value.trim() || null;
    if (p.length === 1 && num(p[0])) port = +p[0];
    else if (p.length === 2 && num(p[0]) && num(p[1])) { port = +p[0]; loc = loc || +p[1]; }
    else if (p.length === 2 && num(p[1])) { host = p[0]; port = +p[1]; }
    else if (p.length === 3 && num(p[1]) && num(p[2])) { host = p[0]; port = +p[1]; loc = loc || +p[2]; }
    if (port === null) { toast("use 8080, 8080:9000 (remote:local), gpu042:8888 or gpu042:8888:9000"); return; }
    const r = await api("forward", {conn: c.id, port, target: host, local: loc});
    if (r.ok) { target.value = ""; local.value = ""; toast("forwarded to localhost:" + r.local); }
  };
  target.addEventListener("keydown", e => { if (e.key === "Enter") go(); });
  local.addEventListener("keydown", e => { if (e.key === "Enter") go(); });
  return h("div", {class: "addform"}, target, local, h("button", {class: "primary", onclick: go}, "Forward"));
}

function connCard(c) {
  const who = [c.user && c.rhost ? c.user + "@" + c.rhost : (c.rhost || ""), c.ip].filter(Boolean).join(" · ");
  const card = h("div", {class: "card"},
    h("div", {class: "card-head"},
      h("span", {class: "dot " + (c.status === "ok" ? "ok" : c.status === "noshell" ? "warn" : "")}),
      h("span", {class: "card-title"}, c.dest),
      h("span", {class: "sub"}, who),
      h("span", {class: "spacer"}),
      c.status === "ok" ? h("a", {class: "btn", href: fileUrl(c.id, (c.home || "").replace(/\/$/, "") + "/"), target: "_blank", title: "browse files"}, "files") : null,
    ),
    h("div", {class: "badges"}, statusBadges(c)));
  if (c.status !== "ok") return card;
  const fw = h("div", {class: "rows"}, h("div", {class: "rows-title"}, "Forwards"));
  if (!c.forwards.length) fw.append(h("div", {class: "empty"}, "none yet"));
  for (const f of c.forwards) fw.append(forwardRow(c, f));
  const notForwarded = c.detected.filter(d => !d.forwarded_local);
  const det = h("div", {class: "rows"}, h("div", {class: "rows-title"}, "Listening on " + (c.rhost || c.dest),
    " ", h("button", {class: "icon", title: "rescan", onclick: () => api("detect", {conn: c.id})}, "↻")));
  if (!c.detected.length) det.append(h("div", {class: "empty"}, "no ports detected"));
  for (const d of c.detected) det.append(detectedRow(c, d));
  const skillOn = (state.settings.agent_skill_hosts || []).some(x => x === c.dest || x === c.id);
  const skill = h("div", {class: "rows"}, h("div", {class: "rows-title"}, "Agent skill"),
    h("div", {class: "row"},
      h("span", {class: "grow sub", title: "~/.claude/skills/sshelper and ~/.agents/skills/sshelper on " + (c.rhost || c.dest)},
        skillOn ? (c.skill === "installed" ? "agents on " + (c.rhost || c.dest) + " (Claude Code, Codex, …) know how to push here"
                   : c.skill.startsWith("error") ? c.skill : "installing…")
                : "off: agents on " + (c.rhost || c.dest) + " don't know about sshelper"),
      h("button", {class: skillOn ? "on" : "", onclick: () => api("agent", {conn: c.id, enabled: !skillOn})},
        skillOn ? "on" : "off")));
  card.append(fw, det, skill, addForm(c));
  return card;
}

function renderConnections() {
  const key = JSON.stringify([state.connections, state.uncontrolled]);
  if (key === lastConnKey) return;
  lastConnKey = key;
  const keep = {};
  let focused = document.activeElement && document.activeElement.dataset ? document.activeElement.dataset.keep : null;
  document.querySelectorAll("#conns [data-keep]").forEach(i => { keep[i.dataset.keep] = i.value; });
  const root = document.getElementById("conns");
  root.replaceChildren(...state.connections.map(connCard));
  if (!state.connections.length) {
    root.append(h("div", {class: "card"},
      h("div", {class: "card-title"}, "No controllable ssh connections"),
      h("p", {class: "sub"}, "Connect with plain ", h("code", {}, "ssh host"), " in any terminal. ",
        "If nothing shows up, run ", h("code", {}, "sshelper setup"), " once and reconnect.")));
  }
  root.querySelectorAll("[data-keep]").forEach(i => {
    if (keep[i.dataset.keep] !== undefined) i.value = keep[i.dataset.keep];
    if (focused && i.dataset.keep === focused) i.focus();
  });
  const unc = document.getElementById("uncontrolled");
  unc.replaceChildren();
  if (state.uncontrolled.length) {
    unc.append(h("p", {class: "sub"}, "Not controllable (opened before ", h("code", {}, "sshelper setup"),
      " or with their own ControlPath; reconnect to control them): ",
      state.uncontrolled.map(u => u.dest).join(", ")));
  }
}

// ---------------------------------------------------------------- pushes

function mediaFigure(push, item) {
  const conn = push.from.conn;
  const url = fileUrl(conn, item.path, item.meta);
  const cap = item.caption || item.path.split("/").pop();
  const kind = kindOf(item.path);
  const fig = h("figure", {});
  if (kind === "video") {
    const v = h("video", {controls: true, preload: "metadata", src: url, playsinline: true});
    v.addEventListener("error", () => fig.append(h("div", {class: "warnline"},
      "The browser cannot play this video. If it was written with OpenCV 'mp4v', re-encode it as H.264 (avc1) or webm.")));
    fig.append(v);
  } else if (kind === "image") {
    fig.append(h("a", {href: url, target: "_blank"}, h("img", {src: url, alt: cap, loading: "lazy"})));
  } else {
    fig.append(h("audio", {controls: true, preload: "none", src: url, style: "width:100%"}));
  }
  fig.append(h("figcaption", {}, cap, " ", h("a", {href: url, target: "_blank"}, "open"),
    " · ", h("a", {href: url + (url.includes("?") ? "&" : "?") + "download=1"}, "download")));
  return fig;
}

function pathItem(push, item) {
  const conn = push.from.conn;
  const meta = item.meta || {};
  const url = fileUrl(conn, item.path, meta);
  const label = item.caption ? item.caption : item.path;
  const parts = [h("span", {class: "badge"}, meta.kind === "dir" ? "folder" : meta.kind === "missing" ? "missing" : "file")];
  parts.push(h("a", {class: "path mono", href: url, target: "_blank", title: item.path}, label));
  if (meta.kind === "file") parts.push(h("span", {class: "sub"}, size(meta.size)));
  if (meta.kind === "file" && kindOf(item.path) === "text")
    parts.push(h("a", {href: fileUrl(conn, item.path) + "?follow=1", target: "_blank"}, "follow"));
  if (meta.kind === "file") parts.push(h("a", {href: url + "&download=1"}, "download"));
  return h("div", {class: "item"}, parts);
}

function portItem(push, item) {
  const c = connById(push.from.conn);
  const host = item.host || "localhost";
  const f = c && c.forwards.find(f => f.rport === item.port && f.target === host);
  const label = (item.caption ? item.caption + " " : "") + host + ":" + item.port;
  const parts = [h("span", {class: "badge"}, "port"), h("span", {class: "mono"}, label)];
  if (f) parts.push(h("a", {class: "btn", href: "http://localhost:" + f.local + "/", target: "_blank"}, "open localhost:" + f.local));
  else if (c && c.status === "ok") parts.push(h("button", {onclick: async () => {
      const r = await api("forward", {conn: c.id, port: item.port, target: host});
      if (r.ok) window.open(r.url, "_blank");
    }}, "forward & open"));
  else parts.push(h("span", {class: "sub"}, "host offline"));
  return h("div", {class: "item"}, parts);
}

function boxEl(push) {
  const from = push.from || {};
  const fromText = "from " + (from.dest || from.conn) + " (" +
    [from.ip, from.user ? "user " + from.user : ""].filter(Boolean).join(", ") + ")";
  const media = h("div", {class: "media"});
  const items = h("div", {class: "items"});
  for (const item of push.items) {
    if (item.type === "path" && (item.meta || {}).kind === "file" && ["video", "image", "audio"].includes(kindOf(item.path)))
      media.append(mediaFigure(push, item));
    else if (item.type === "path") items.append(pathItem(push, item));
    else if (item.type === "port") items.append(portItem(push, item));
    else if (item.type === "text") items.append(h("pre", {class: "text"}, (item.caption ? item.caption + ": " : "") + item.text));
    else if (item.type === "url") items.append(h("div", {class: "item"}, h("span", {class: "badge"}, "link"),
      h("a", {href: item.url, target: "_blank", rel: "noopener noreferrer", class: "path"}, item.caption || item.url)));
  }
  const timeEl = h("span", {class: "box-time", title: new Date(push.time * 1000).toLocaleString(), "data-ts": push.time}, rel(push.time));
  return h("div", {class: "card", id: "p-" + push.id},
    h("div", {class: "box-head"},
      h("a", {class: "box-project", href: "/" + push.project, onclick: (e) => { e.preventDefault(); go("/" + push.project); }}, push.project),
      push.title ? h("span", {class: "box-title"}, push.title) : null,
      timeEl,
      h("button", {class: "icon", title: "re-check files", onclick: () => api("push/restat", {id: push.id})}, "↻"),
      h("button", {class: "icon", title: "remove box", onclick: () => api("push/delete", {id: push.id})}, "✕")),
    h("div", {class: "box-from"}, fromText, push.sender ? h("span", {class: "via"}, " · via " + push.sender) : null),
    media.childElementCount ? media : null,
    items.childElementCount ? items : null);
}

function connKeyFor(push) {
  // port items depend on forwards; keep boxes stable unless their forward state changes
  const c = connById(push.from.conn);
  if (!push.items.some(i => i.type === "port")) return "";
  return JSON.stringify(c ? [c.status, c.forwards] : null);
}

function renderPushes() {
  const proj = project();
  const all = state.pushes.slice().reverse();
  const counts = {};
  for (const p of all) counts[p.project] = (counts[p.project] || 0) + 1;
  const hosts = [...new Set(all.map(p => p.from.dest || p.from.conn))];
  const chipKey = JSON.stringify([proj, counts, hosts, filterHost]);
  if (chipKey !== lastChipKey) {
    lastChipKey = chipKey;
    const chips = document.getElementById("chips");
    chips.replaceChildren(
      h("span", {class: "chip" + (proj ? "" : " active"), onclick: () => go("/")}, "All", h("span", {class: "n"}, all.length)),
      ...Object.keys(counts).sort().map(name => h("span", {class: "chip" + (proj === name ? " active" : ""),
        onclick: () => go("/" + name)}, name, h("span", {class: "n"}, counts[name]))));
    if (hosts.length > 1) {
      chips.append(h("span", {class: "sub", style: "margin-left:8px"}, "from:"));
      for (const host of ["", ...hosts]) chips.append(h("span", {class: "chip" + (filterHost === host ? " active" : ""),
        onclick: () => { filterHost = host; lastChipKey = ""; lastPushKey = ""; render(); }}, host || "any"));
    }
    if (proj) chips.append(h("button", {class: "icon", style: "margin-left:auto", title: "delete every box in " + proj,
      onclick: () => { if (confirm("Remove all boxes in " + proj + "?")) api("project/delete", {project: proj}); }}, "clear project"));
  }
  const shown = all.filter(p => (!proj || p.project === proj) && (!filterHost || (p.from.dest || p.from.conn) === filterHost));
  const pushKey = JSON.stringify([proj, filterHost, shown.map(p => [p.id, p.items, connKeyFor(p)])]);
  if (pushKey === lastPushKey) return;
  lastPushKey = pushKey;
  const root = document.getElementById("boxes");
  const next = [];
  for (const p of shown) {
    const sig = JSON.stringify([p.items, p.title, connKeyFor(p)]);
    let entry = boxEls.get(p.id);
    if (!entry || entry.sig !== sig) { entry = {el: boxEl(p), sig}; boxEls.set(p.id, entry); }
    next.push(entry.el);
  }
  for (const id of [...boxEls.keys()]) if (!state.pushes.some(p => p.id === id)) boxEls.delete(id);
  if (!next.length) {
    root.replaceChildren(h("div", {class: "card"},
      h("div", {class: "card-title"}, proj ? "Nothing in " + proj + " yet" : "Nothing pushed yet"),
      h("p", {class: "sub"}, "On a connected machine, run ",
        h("code", {}, "cat ~/.sshelper/README.md"),
        " to see how to push files, videos, ports and notes here. Point your agent at it.")));
    return;
  }
  // reorder without recreating existing elements (keeps videos playing)
  root.querySelectorAll(":scope > .card:not([id])").forEach(e => e.remove());
  next.forEach((el, i) => { if (root.children[i] !== el) root.insertBefore(el, root.children[i] || null); });
  while (root.children.length > next.length) root.lastChild.remove();
}

// ---------------------------------------------------------------- shell

function render() {
  if (!state) return;
  document.getElementById("laptop").textContent = "on " + state.laptop + " · " + state.address;
  const n = document.getElementById("notice");
  n.replaceChildren(...(state.notice ? [h("div", {class: "notice"}, state.notice)] : []));
  const proj = project();
  document.getElementById("conn-section").style.display = proj ? "none" : "";
  document.getElementById("pushes-title").replaceChildren(
    ...(proj ? [h("a", {href: "/", class: "back", onclick: (e) => { e.preventDefault(); go("/"); }}, "← all"), " " + proj] : ["Projects"]));
  document.title = proj ? proj + " · sshelper" : "sshelper";
  renderConnections();
  renderPushes();
  const s = state.settings;
  const port = document.getElementById("set-port"), br = document.getElementById("set-browser");
  if (document.activeElement !== port) port.value = s.port;
  if (document.activeElement !== br) br.value = s.browser;
  document.getElementById("set-push").checked = s.push_channel;
}

function go(path) { history.pushState(null, "", path); lastChipKey = ""; lastPushKey = ""; render(); window.scrollTo(0, 0); }
window.addEventListener("popstate", () => { lastChipKey = ""; lastPushKey = ""; render(); });

async function load() {
  try {
    const r = await fetch("/api/state");
    state = await r.json();
    render();
    setLive(true);
  } catch (e) { setLive(false); }
}

function setLive(ok) {
  document.getElementById("livedot").className = "dot " + (ok ? "ok" : "bad");
  document.getElementById("livetext").textContent = ok ? "live" : "daemon offline";
}

let pending = null;
function connect() {
  const es = new EventSource("/api/events");
  es.onmessage = () => { clearTimeout(pending); pending = setTimeout(load, 120); };
  es.onerror = () => { setLive(false); };
  es.onopen = () => load();
}

document.getElementById("set-save").addEventListener("click", async () => {
  const r = await api("settings", {
    port: +document.getElementById("set-port").value,
    browser: document.getElementById("set-browser").value,
    push_channel: document.getElementById("set-push").checked});
  if (r.ok) toast(r.restart ? "Saved. Run `sshelper daemon restart` to use the new port." : "Saved.");
});

setInterval(() => document.querySelectorAll("[data-ts]").forEach(e => { e.textContent = rel(+e.dataset.ts); }), 30000);
load();
connect();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# client side: talk to the daemon
# ---------------------------------------------------------------------------

_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class DaemonError(RuntimeError):
    pass


def daemon_info() -> dict | None:
    info = read_json(state_dir() / "daemon.json", None)
    if not isinstance(info, dict) or not isinstance(info.get("pid"), int):
        return None
    if not pid_alive(info["pid"]):
        return None
    return info


def api_call(info: dict, method: str, path: str, body: dict | None = None,
             timeout: float = 20) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        f"http://127.0.0.1:{info['port']}{path}", data=data, method=method,
        headers={"Content-Type": "application/json", "X-Session": info.get("session", "")})
    try:
        with _OPENER.open(req, timeout=timeout) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode())
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            payload = {}
        raise DaemonError(payload.get("error") or f"HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
        raise DaemonError(f"daemon not reachable: {exc}") from None


def daemon_ping(info: dict) -> bool:
    try:
        return bool(api_call(info, "GET", "/api/ping", timeout=3).get("ok"))
    except DaemonError:
        return False


def start_daemon() -> dict:
    ensure_private_dir(state_dir())
    log_path = state_dir() / "daemon.log"
    try:
        if log_path.stat().st_size > 1_000_000:
            log_path.replace(log_path.with_suffix(".log.1"))
    except OSError:
        pass
    script = current_executable_path()
    with log_path.open("a") as log_handle:
        proc = subprocess.Popen(
            [sys.executable, str(script), "daemon", "run"],
            stdin=subprocess.DEVNULL, stdout=log_handle, stderr=subprocess.STDOUT,
            start_new_session=True, close_fds=True,
            env=dict(os.environ, SSHELPER_NO_AUTO_UPDATE="1"))
    deadline = time.time() + 8
    while time.time() < deadline:
        info = daemon_info()
        if info and info["pid"] == proc.pid and daemon_ping(info):
            return info
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    raise DaemonError(f"daemon did not start; see {log_path}")


def stop_daemon(info: dict) -> bool:
    try:
        os.kill(info["pid"], signal.SIGTERM)
    except ProcessLookupError:
        return True
    deadline = time.time() + 12
    while time.time() < deadline:
        if not pid_alive(info["pid"]):
            return True
        time.sleep(0.1)
    return False


def ensure_daemon() -> dict:
    info = daemon_info()
    if info and daemon_ping(info):
        if info.get("version") == __version__:
            return info
        stop_daemon(info)  # restart a daemon from an older/newer version
    return start_daemon()


def wait_for_scan(info: dict, seconds: float = 6) -> dict:
    deadline = time.time() + seconds
    state = api_call(info, "GET", "/api/state")
    while time.time() < deadline:
        if state.get("scans", 0) > 0 and not any(
                c["status"] == "connecting" or (
                    c["status"] == "ok" and not c["push"]["ok"] and not c["push"]["error"]
                    and state["settings"]["push_channel"]
                    and c["dest"] not in state["settings"]["push_disabled_hosts"]
                    and c["id"] not in state["settings"]["push_disabled_hosts"])
                for c in state["connections"]):
            break
        time.sleep(0.25)
        state = api_call(info, "GET", "/api/state")
    return state


def open_url(url: str, browser: str = "") -> None:
    try:
        if browser:
            cmd = shlex.split(browser) + [url]
        elif shutil.which("xdg-open"):
            cmd = ["xdg-open", url]
        elif sys.platform == "darwin":
            cmd = ["open", url]
        else:
            webbrowser.open(url)
            return
        subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except (OSError, ValueError):
        webbrowser.open(url)


def parse_forward_spec(spec: str) -> tuple[str, int, int | None]:
    """PORT | PORT:LOCAL | HOST:PORT | HOST:PORT:LOCAL -> (target, port, local)."""
    parts = spec.split(":")
    try:
        if len(parts) == 1:
            return "localhost", int(parts[0]), None
        if len(parts) == 2:
            if parts[0].isdigit():
                return "localhost", int(parts[0]), int(parts[1])
            return parts[0], int(parts[1]), None
        if len(parts) == 3:
            return parts[0], int(parts[1]), int(parts[2])
    except ValueError:
        pass
    raise ValueError(f"bad forward spec {spec!r}; use PORT, PORT:LOCAL, HOST:PORT or HOST:PORT:LOCAL")


ARROW = "→"


def describe_forward(f: dict) -> str:
    target = "(opened outside sshelper)" if f["external"] else f"{f['target']}:{f['rport']}"
    return f"localhost:{f['local']} {ARROW} {target}" + ("  [pinned]" if f["pinned"] else "")


def conn_summary(c: dict) -> str:
    who = f"{c['user']}@{c['rhost']}" if c["user"] else c["rhost"]
    bits = [c["status"]]
    if c["local_fwd"] == "blocked":
        bits.append("forwarding blocked")
    if c["push"]["ok"]:
        bits.append(f"push :{c['push']['port']}")
    elif c["remote_fwd"] == "blocked":
        bits.append("reverse forwarding blocked")
    return f"{who}  {c['ip']}  " + ", ".join(bits)


# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------


class Tui:
    def __init__(self, info: dict, message: str = ""):
        self.info = info
        self.state: dict | None = None
        self.stack: list[tuple] = [("home",)]
        self.sel: dict[tuple, int] = {}
        self.offset = 0
        self.message = message
        self.last_fetch = 0.0
        self.scr = None

    # -- data -----------------------------------------------------------------

    def fetch(self) -> None:
        self.last_fetch = time.time()
        try:
            self.state = api_call(self.info, "GET", "/api/state", timeout=5)
        except DaemonError as exc:
            try:
                self.info = ensure_daemon()
                self.state = api_call(self.info, "GET", "/api/state", timeout=5)
            except DaemonError:
                self.message = str(exc)

    def act(self, path: str, body: dict, ok: str = "") -> dict | None:
        try:
            result = api_call(self.info, "POST", path, body)
        except DaemonError as exc:
            self.message = f"error: {exc}"
            return None
        if ok:
            self.message = ok.format(**result) if result else ok
        self.fetch()
        return result

    def conn(self, conn_id: str) -> dict | None:
        for c in (self.state or {}).get("connections", []):
            if c["id"] == conn_id:
                return c
        return None

    # -- rows -----------------------------------------------------------------

    def rows(self) -> tuple[str, list[dict], str]:
        st = self.state or {"connections": [], "uncontrolled": [], "pushes": [], "address": "",
                             "settings": {}}
        view = self.stack[-1]
        rows: list[dict] = []

        def head(text: str) -> None:
            rows.append({"text": text, "head": True})

        def row(text: str, kind: str, **data: object) -> None:
            rows.append({"text": text, "kind": kind, **data})

        if view[0] == "home":
            head("Connections")
            for c in st["connections"]:
                row(f"{c['dest']:<18} {conn_summary(c)}", "conn", id=c["id"])
            if not st["connections"]:
                rows.append({"text": "  none: connect with `ssh host`; run `sshelper setup` once if nothing shows",
                             "dim": True})
            for u in st["uncontrolled"]:
                rows.append({"text": f"{u['dest']:<18} not controllable (reconnect after setup)", "dim": True})
            head("")
            projects = {p["project"] for p in st["pushes"]}
            row(f"Projects  ({len(projects)} projects, {len(st['pushes'])} boxes)", "projects")
            row(f"Open dashboard  {st['address']}", "web")
            row("Settings", "settings")
            return "home", rows, "enter open · w dashboard · q quit"
        if view[0] == "conn":
            c = self.conn(view[1])
            if c is None:
                rows.append({"text": "connection is gone", "dim": True})
                return view[1], rows, "b back"
            head(f"{c['dest']}  {conn_summary(c)}")
            if c["push"]["error"]:
                rows.append({"text": f"push channel: {c['push']['error']}", "dim": True})
            head("Forwards")
            for f in c["forwards"]:
                row(describe_forward(f), "fwd", conn=c["id"], local=f["local"], external=f["external"],
                    pinned=f["pinned"])
            if not c["forwards"]:
                rows.append({"text": "  none", "dim": True})
            head(f"Listening on {c['rhost'] or c['dest']}")
            for d in c["detected"]:
                label = str(d["port"]) if d["target"] == "localhost" else f"{d['target']}:{d['port']}"
                extra = f"  (forwarded {ARROW} localhost:{d['forwarded_local']})" if d.get("forwarded_local") else ""
                row(f"{label:<8} {d['name']}{extra}", "det", conn=c["id"], port=d["port"],
                    target=d["target"], local=d.get("forwarded_local"))
            if not c["detected"]:
                rows.append({"text": "  no ports detected", "dim": True})
            head("")
            row("+ add forward…", "add", conn=c["id"])
            skill_on = c["dest"] in st["settings"].get("agent_skill_hosts", []) or \
                c["id"] in st["settings"].get("agent_skill_hosts", [])
            row(f"agent skill: {'on' if skill_on else 'off'}"
                + (f"  ({c['skill']})" if c.get("skill") else ""), "skill", conn=c["id"], on=skill_on)
            row("browse files in browser", "files", conn=c["id"], home=c.get("home") or "/")
            return c["dest"], rows, "enter forward/open · a add · d close · p pin · o open · r rescan · b back"
        if view[0] == "projects":
            counts: dict[str, list] = {}
            for p in st["pushes"]:
                counts.setdefault(p["project"], []).append(p)
            for name in sorted(counts, key=lambda n: -max(p["time"] for p in counts[n])):
                latest = max(p["time"] for p in counts[name])
                row(f"{name:<24} {len(counts[name]):>3} boxes   last {ago(latest)}", "project", name=name)
            if not counts:
                rows.append({"text": "  nothing pushed yet", "dim": True})
            return "projects", rows, "enter open · o open in browser · d delete project · b back"
        if view[0] == "project":
            pushes = [p for p in reversed(st["pushes"]) if p["project"] == view[1]]
            for p in pushes:
                stamp = time.strftime("%m-%d %H:%M", time.localtime(p["time"]))
                via = f" via {p['sender']}" if p["sender"] else ""
                row(f"{stamp}  {p['title'] or '(untitled)':<30} from {p['from']['dest']}{via}"
                    f"  [{len(p['items'])}]", "box", id=p["id"])
            return view[1], rows, "enter items · o open in browser · d delete box · b back"
        if view[0] == "box":
            push = next((p for p in st["pushes"] if p["id"] == view[1]), None)
            if push is None:
                rows.append({"text": "box was removed", "dim": True})
                return "box", rows, "b back"
            head(f"{push['project']} · {push['title'] or '(untitled)'} · from {push['from']['dest']}")
            for item in push["items"]:
                cap = f"  ({item['caption']})" if item.get("caption") else ""
                if item["type"] == "path":
                    meta = item.get("meta") or {}
                    size = f"  {human_size(meta['size'])}" if meta.get("kind") == "file" else ""
                    row(f"{meta.get('kind', 'path'):<7} {item['path']}{size}{cap}", "item", push=push, item=item)
                elif item["type"] == "port":
                    row(f"port    {item['host']}:{item['port']}{cap}", "item", push=push, item=item)
                elif item["type"] == "url":
                    row(f"link    {item['url']}{cap}", "item", push=push, item=item)
                else:
                    first = item["text"].splitlines()[0] if item["text"] else ""
                    rows.append({"text": f"text    {first}{cap}", "dim": False})
            return push["project"], rows, "enter open in browser · b back"
        if view[0] == "settings":
            s = st["settings"]
            row(f"Dashboard port   {s.get('port')}   ({st['address']})", "set-port")
            row(f"Browser command  {s.get('browser') or '(system default)'}", "set-browser")
            row(f"Push channel     {'on' if s.get('push_channel') else 'off'}", "set-push")
            head("")
            rows.append({"text": "Port 80 (no port in the URL) needs `sshelper setup --port 80` once.",
                         "dim": True})
            return "settings", rows, "enter change · b back"
        return "?", rows, "b back"

    # -- drawing -----------------------------------------------------------------

    def draw(self) -> None:
        scr = self.scr
        scr.erase()
        height, width = scr.getmaxyx()
        title, rows, keys = self.rows()
        selectable = [i for i, r in enumerate(rows) if r.get("kind")]
        view = self.stack[-1]
        sel = self.sel.get(view, selectable[0] if selectable else 0)
        if selectable and sel not in selectable:
            sel = min(selectable, key=lambda i: abs(i - sel))
        self.sel[view] = sel
        laptop = (self.state or {}).get("laptop", "")
        bar = f" sshelper · {title}"
        right = f"{laptop} "
        self.put(0, 0, (bar + " " * width)[: max(0, width - len(right))] + right, curses.A_REVERSE)
        body_h = max(1, height - 4)
        if sel < self.offset:
            self.offset = sel
        elif sel >= self.offset + body_h:
            self.offset = sel - body_h + 1
        self.offset = max(0, min(self.offset, max(0, len(rows) - body_h)))
        for line, idx in enumerate(range(self.offset, min(len(rows), self.offset + body_h))):
            r = rows[idx]
            attr = curses.A_NORMAL
            text = r["text"]
            if r.get("head"):
                attr = curses.A_BOLD
            elif r.get("dim"):
                attr = curses.A_DIM
            else:
                text = "  " + text
            if idx == sel and r.get("kind"):
                attr = curses.A_REVERSE
                text = text.ljust(width - 1)
            self.put(2 + line, 0, text, attr)
        self.put(height - 2, 0, keys, curses.A_DIM)
        if self.message:
            self.put(height - 1, 0, self.message, curses.A_BOLD)
        scr.refresh()

    def put(self, y: int, x: int, text: str, attr: int = 0) -> None:
        height, width = self.scr.getmaxyx()
        if 0 <= y < height and x < width:
            try:
                self.scr.addnstr(y, x, text, max(0, width - x - 1), attr)
            except curses.error:
                pass

    def prompt(self, label: str, initial: str = "") -> str | None:
        scr = self.scr
        text = initial
        curses.curs_set(1)
        scr.timeout(-1)
        try:
            while True:
                height, width = scr.getmaxyx()
                scr.move(height - 1, 0)
                scr.clrtoeol()
                self.put(height - 1, 0, label + text, curses.A_BOLD)
                try:
                    scr.move(height - 1, min(width - 1, len(label) + len(text)))
                except curses.error:
                    pass
                key = scr.get_wch()
                if key in ("\n", "\r", curses.KEY_ENTER):
                    return text.strip()
                if key == "\x1b":
                    return None
                if key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                    text = text[:-1]
                elif isinstance(key, str) and key.isprintable():
                    text += key
        finally:
            curses.curs_set(0)
            scr.timeout(500)

    def confirm(self, question: str) -> bool:
        answer = self.prompt(f"{question} [y/N] ")
        return bool(answer) and answer.lower().startswith("y")

    # -- input ---------------------------------------------------------------------

    def run(self) -> int:
        return curses.wrapper(self._main)

    def _main(self, scr) -> int:
        self.scr = scr
        curses.curs_set(0)
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        scr.timeout(500)
        self.fetch()
        while True:
            if time.time() - self.last_fetch > 1.5:
                self.fetch()
            self.draw()
            try:
                key = scr.get_wch()
            except curses.error:
                continue
            if key == curses.KEY_RESIZE:
                continue
            if not self.handle(key):
                return 0

    def selected(self) -> dict | None:
        _, rows, _ = self.rows()
        idx = self.sel.get(self.stack[-1])
        if idx is None or idx >= len(rows):
            return None
        return rows[idx] if rows[idx].get("kind") else None

    def move(self, delta: int) -> None:
        _, rows, _ = self.rows()
        selectable = [i for i, r in enumerate(rows) if r.get("kind")]
        if not selectable:
            return
        view = self.stack[-1]
        current = self.sel.get(view, selectable[0])
        pos = selectable.index(current) if current in selectable else 0
        self.sel[view] = selectable[max(0, min(len(selectable) - 1, pos + delta))]

    def browser(self) -> str:
        return ((self.state or {}).get("settings") or {}).get("browser", "")

    def handle(self, key: object) -> bool:
        if key in ("q", "Q"):
            return False
        self.message = ""
        if key in (curses.KEY_UP, "k"):
            self.move(-1)
        elif key in (curses.KEY_DOWN, "j"):
            self.move(1)
        elif key in (curses.KEY_PPAGE,):
            self.move(-10)
        elif key in (curses.KEY_NPAGE,):
            self.move(10)
        elif key in ("b", "B", "h", curses.KEY_LEFT, curses.KEY_BACKSPACE, "\x7f", "\x1b"):
            if len(self.stack) > 1:
                self.stack.pop()
        elif key in ("w", "W"):
            open_url((self.state or {}).get("address", ""), self.browser())
            self.message = "opened dashboard"
        elif key in ("R",):
            self.fetch()
        elif key in ("\n", "\r", curses.KEY_ENTER, curses.KEY_RIGHT, "l"):
            self.enter()
        elif isinstance(key, str):
            self.key(key)
        return True

    def enter(self) -> None:
        r = self.selected()
        if not r:
            return
        kind = r["kind"]
        address = (self.state or {}).get("address", "")
        if kind == "conn":
            self.stack.append(("conn", r["id"]))
        elif kind == "projects":
            self.stack.append(("projects",))
        elif kind == "web":
            open_url(address, self.browser())
            self.message = "opened dashboard"
        elif kind == "settings":
            self.stack.append(("settings",))
        elif kind == "fwd":
            open_url(f"http://localhost:{r['local']}/", self.browser())
            self.message = f"opened localhost:{r['local']}"
        elif kind == "det":
            if r.get("local"):
                open_url(f"http://localhost:{r['local']}/", self.browser())
            else:
                self.act("/api/forward", {"conn": r["conn"], "port": r["port"], "target": r["target"]},
                         "forwarded to localhost:{local}")
        elif kind == "add":
            self.add_forward(r["conn"])
        elif kind == "skill":
            self.act("/api/agent", {"conn": r["conn"], "enabled": not r["on"]},
                     "agent skill " + ("off" if r["on"] else "on"))
        elif kind == "files":
            open_url(address.rstrip("/") + file_url(r["conn"], r["home"].rstrip("/") + "/"), self.browser())
        elif kind == "project":
            self.stack.append(("project", r["name"]))
        elif kind == "box":
            self.stack.append(("box", r["id"]))
        elif kind == "item":
            self.open_item(r["push"], r["item"])
        elif kind == "set-port":
            value = self.prompt("Dashboard port: ", str(self.state["settings"]["port"]))
            if value:
                try:
                    result = self.act("/api/settings", {"port": int(value)})
                except ValueError:
                    self.message = "not a number"
                    return
                if result and result.get("restart"):
                    if self.confirm("Restart the daemon now to use the new port?"):
                        stop_daemon(self.info)
                        self.info = start_daemon()
                        self.fetch()
                        self.message = f"dashboard now at {self.state['address']}"
        elif kind == "set-browser":
            value = self.prompt("Browser command (empty = system default): ",
                                self.state["settings"].get("browser", ""))
            if value is not None:
                self.act("/api/settings", {"browser": value}, "saved")
        elif kind == "set-push":
            self.act("/api/settings", {"push_channel": not self.state["settings"]["push_channel"]},
                     "saved; applies to new connections")

    def key(self, key: str) -> None:
        r = self.selected()
        view = self.stack[-1]
        if key == "a" and view[0] == "conn":
            self.add_forward(view[1])
        elif key == "r" and view[0] == "conn":
            self.act("/api/detect", {"conn": view[1]}, "rescanned")
        elif key == "d" and r and r["kind"] == "fwd":
            self.act("/api/close", {"conn": r["conn"], "local": r["local"]}, "forward closed")
        elif key == "p" and r and r["kind"] == "fwd":
            if r["external"]:
                self.message = "only forwards opened by sshelper can be pinned"
            else:
                self.act("/api/pin", {"conn": r["conn"], "local": r["local"], "pinned": not r["pinned"]},
                         "unpinned" if r["pinned"] else "pinned: reopens when the host reconnects")
        elif key == "o" and r:
            address = (self.state or {}).get("address", "").rstrip("/")
            if r["kind"] in ("fwd", "det") and r.get("local"):
                open_url(f"http://localhost:{r['local']}/", self.browser())
            elif r["kind"] == "project":
                open_url(f"{address}/{r['name']}", self.browser())
            elif r["kind"] == "box":
                open_url(f"{address}/{view[1]}#p-{r['id']}", self.browser())
            elif r["kind"] == "item":
                self.open_item(r["push"], r["item"])
        elif key == "d" and r and r["kind"] == "box":
            if self.confirm("Remove this box?"):
                self.act("/api/push/delete", {"id": r["id"]}, "removed")
        elif key == "d" and r and r["kind"] == "project":
            if self.confirm(f"Remove every box in {r['name']}?"):
                self.act("/api/project/delete", {"project": r["name"]}, "removed")

    def add_forward(self, conn_id: str) -> None:
        spec = self.prompt("Forward (PORT, PORT:LOCAL, HOST:PORT, HOST:PORT:LOCAL): ")
        if not spec:
            return
        try:
            target, port, local = parse_forward_spec(spec)
        except ValueError as exc:
            self.message = str(exc)
            return
        self.act("/api/forward", {"conn": conn_id, "port": port, "target": target, "local": local},
                 "forwarded to localhost:{local}")

    def open_item(self, push: dict, item: dict) -> None:
        address = (self.state or {}).get("address", "").rstrip("/")
        if item["type"] == "path":
            open_url(address + file_url(push["from"]["conn"], item["path"], item.get("meta")), self.browser())
        elif item["type"] == "url":
            open_url(item["url"], self.browser())
        elif item["type"] == "port":
            c = self.conn(push["from"]["conn"])
            fwd = next((f for f in (c or {}).get("forwards", [])
                        if f["rport"] == item["port"] and f["target"] == item["host"]), None)
            if fwd:
                open_url(f"http://localhost:{fwd['local']}/", self.browser())
            elif c:
                result = self.act("/api/forward", {"conn": c["id"], "port": item["port"],
                                                   "target": item["host"]}, "forwarded to localhost:{local}")
                if result:
                    open_url(result["url"], self.browser())
            else:
                self.message = "host is offline"


def ago(ts: float) -> str:
    seconds = max(0, time.time() - ts)
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)} h ago"
    return time.strftime("%Y-%m-%d", time.localtime(ts))


# ---------------------------------------------------------------------------
# commands
# ---------------------------------------------------------------------------


def cmd_tui(args: argparse.Namespace) -> int:
    global ARROW
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return cmd_ls(args)
    if "utf" not in (sys.stdout.encoding or "").lower():
        ARROW = "->"
    import locale
    locale.setlocale(locale.LC_ALL, "")
    try:
        info = ensure_daemon()
    except DaemonError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return 1
    return Tui(info, getattr(args, "startup_message", "")).run()


def cmd_ls(args: argparse.Namespace) -> int:
    try:
        info = ensure_daemon()
        state = wait_for_scan(info)
    except DaemonError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return 1
    if getattr(args, "json", False):
        print(json.dumps({k: state[k] for k in ("connections", "uncontrolled", "address")}, indent=2))
        return 0
    if not state["connections"]:
        print("no controllable ssh connections")
        print("  connect with `ssh host`; if it does not show up, run `sshelper setup` and reconnect")
    for c in state["connections"]:
        print(f"{c['dest']}  {conn_summary(c)}")
        if c["push"]["error"]:
            print(f"  push channel: {c['push']['error']}")
        for f in c["forwards"]:
            print(f"  forward    {describe_forward(f)}")
        for d in c["detected"]:
            if not d.get("forwarded_local"):
                label = str(d["port"]) if d["target"] == "localhost" else f"{d['target']}:{d['port']}"
                print(f"  listening  {label:<8} {d['name']}")
    for u in state["uncontrolled"]:
        print(f"{u['dest']}  not controllable (opened before setup or own ControlPath; reconnect)")
    print(f"dashboard: {state['address']}")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    try:
        target, port, local = parse_forward_spec(args.spec)
        info = ensure_daemon()
        wait_for_scan(info)
        result = api_call(info, "POST", "/api/forward", {
            "conn": args.host, "port": port, "target": target, "local": local, "pin": args.pin})
    except (ValueError, DaemonError) as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return 1
    print(f"localhost:{result['local']} {ARROW} {args.host} {target}:{port}   {result['url']}"
          + ("   (pinned)" if args.pin else ""))
    if args.browser:
        open_url(result["url"], load_settings()["browser"])
    return 0


def cmd_close(args: argparse.Namespace) -> int:
    try:
        info = ensure_daemon()
        state = wait_for_scan(info)
        conn = next((c for c in state["connections"]
                     if args.host in (c["id"], c["dest"], c["rhost"], c["ssh_host"])), None)
        if conn is None:
            raise DaemonError(f"no controllable connection named {args.host!r}")
        if args.all:
            ports = [f["local"] for f in conn["forwards"]]
        elif args.port is not None:
            ports = [args.port]
        else:
            raise DaemonError("give a local port or --all")
        for port in ports:
            api_call(info, "POST", "/api/close", {"conn": conn["id"], "local": port})
            print(f"closed localhost:{port}")
    except DaemonError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return 1
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    try:
        info = ensure_daemon()
        state = wait_for_scan(info)
        if args.action == "status":
            enabled = state["settings"].get("agent_skill_hosts", [])
            for c in state["connections"]:
                on = c["dest"] in enabled or c["id"] in enabled
                print(f"{c['dest']:<18} {'on ' if on else 'off'}  {c.get('skill') or ''}")
            offline = [h for h in enabled if h not in {c["dest"] for c in state["connections"]}]
            for host in offline:
                print(f"{host:<18} on   (not connected; installed on next connect)")
            return 0
        if not args.host:
            raise DaemonError("give a host")
        result = api_call(info, "POST", "/api/agent",
                          {"conn": args.host, "enabled": args.action == "on"})
    except DaemonError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return 1
    print(f"agent skill on {args.host}: {args.action} ({result.get('skill') or 'nothing to do'})")
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    try:
        info = ensure_daemon()
    except DaemonError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return 1
    url = dashboard_url(info["port"], f"/{args.project}" if args.project else "/")
    open_url(url, load_settings()["browser"])
    print(url)
    return 0


def cmd_daemon(args: argparse.Namespace) -> int:
    action = args.action
    if action == "run":
        return run_daemon()
    info = daemon_info()
    if action == "status":
        if info and daemon_ping(info):
            print(f"running: pid {info['pid']}, version {info.get('version')}, "
                  f"{dashboard_url(info['port'])}")
            return 0
        print("not running")
        return 1
    if action == "log":
        path = state_dir() / "daemon.log"
        try:
            print(path.read_text(errors="replace")[-8000:], end="")
        except OSError:
            print(f"no log at {path}")
        return 0
    if action in ("stop", "restart") and info:
        if not stop_daemon(info):
            print("sshelper: daemon did not stop", file=sys.stderr)
            return 1
        print("stopped")
    elif action == "stop":
        print("not running")
    if action in ("start", "restart"):
        try:
            info = ensure_daemon()
        except DaemonError as exc:
            print(f"sshelper: {exc}", file=sys.stderr)
            return 1
        print(f"running: pid {info['pid']}, {dashboard_url(info['port'])}")
    return 0


# -- setup ----------------------------------------------------------------------


def ssh_config_path() -> Path:
    return Path.home() / ".ssh" / "config"


def strip_managed_block(text: str) -> str:
    pattern = re.compile(re.escape(SSH_CONFIG_BEGIN) + r".*?" + re.escape(SSH_CONFIG_END) + r"\n?",
                         re.DOTALL)
    return pattern.sub("", text)


def with_managed_block(text: str) -> str:
    base = strip_managed_block(text)
    if base and not base.endswith("\n"):
        base += "\n"
    if base and not base.endswith("\n\n"):
        base += "\n"
    return base + SSH_CONFIG_BLOCK


def ask(question: str, default: bool = True, assume_yes: bool = False) -> bool:
    if assume_yes:
        return True
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        answer = input(question + suffix).strip().lower()
    except EOFError:
        return default
    return default if not answer else answer.startswith("y")


def unprivileged_port_start() -> int | None:
    try:
        return int(Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text().strip())
    except (OSError, ValueError):
        return None


def enable_low_port(port: int) -> bool:
    current = unprivileged_port_start()
    if current is None or current <= port:
        return True
    print(f"\nPort {port} needs a one-time system change (sudo):")
    print(f"  {SYSCTL_FILE}: {SYSCTL_KEY}={port}")
    try:
        tee = subprocess.run(["sudo", "tee", str(SYSCTL_FILE)], input=f"{SYSCTL_KEY}={port}\n",
                             text=True, stdout=subprocess.DEVNULL)
        if tee.returncode != 0:
            return False
        apply = subprocess.run(["sudo", "sysctl", "-q", "-w", f"{SYSCTL_KEY}={port}"])
        return apply.returncode == 0
    except OSError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return False


def restart_daemon_if_running() -> dict | None:
    info = daemon_info()
    if info:
        stop_daemon(info)
    try:
        return ensure_daemon()
    except DaemonError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return None


def cmd_setup(args: argparse.Namespace) -> int:
    if args.undo:
        return setup_undo(args)
    ssh_dir = Path.home() / ".ssh"
    cfg = ssh_config_path()
    print("sshelper setup\n")

    # 1. ssh config
    text = cfg.read_text() if cfg.exists() else ""
    new_text = with_managed_block(text)
    if SSH_CONFIG_BEGIN in text and strip_managed_block(text) + SSH_CONFIG_BLOCK == new_text \
            and new_text == text:
        print(f"[ok] {cfg} already has the sshelper block")
    else:
        print(f"1. Add this block to the end of {cfg}:\n")
        print("   " + SSH_CONFIG_BLOCK.strip().replace("\n", "\n   ") + "\n")
        print("   It makes every `ssh host` controllable by sshelper. Host-specific settings")
        print("   you already have keep priority.")
        if ask("   Add it?", True, args.yes):
            ensure_private_dir(ssh_dir)
            backup = cfg.with_name("config.sshelper-backup")
            if cfg.exists() and not backup.exists():
                shutil.copy2(cfg, backup)
                print(f"   backup: {backup}")
            cfg.write_text(new_text)
            cfg.chmod(0o600)
            print("   [ok] added")
        else:
            print("   skipped: sshelper only sees connections that use ~/.ssh/cm sockets")
    ensure_private_dir(ssh_dir / "cm")

    # 2. dashboard port
    settings = load_settings()
    port = args.port
    if port is None:
        print("\n2. Dashboard address:")
        print(f"   [1] http://{DASHBOARD_HOST}         needs sudo once (allows port 80)")
        print(f"   [2] http://{DASHBOARD_HOST}:{DEFAULT_PORT}    no sudo")
        default = "1" if settings["port"] == 80 else "2"
        try:
            choice = input(f"   Choose [1/2] (default {default}): ").strip() or default
        except EOFError:
            choice = default
        port = 80 if choice == "1" else DEFAULT_PORT
    if port < 1024 and sys.platform.startswith("linux"):
        if not enable_low_port(port):
            print(f"   could not enable port {port}; using {DEFAULT_PORT} instead")
            port = DEFAULT_PORT
    settings["port"] = port
    save_settings(settings)
    print(f"   [ok] dashboard port {port}")

    # 3. daemon
    info = restart_daemon_if_running()
    if info:
        print(f"\n[ok] daemon running: {dashboard_url(info['port'])}")
        if info["port"] != port:
            print(f"     (port {port} is busy; see `sshelper doctor`)")
    print("\nDone. ssh sessions opened before this setup are not controllable:")
    print("reconnect them. Then run `sshelper` (TUI) or open the dashboard.")
    return 0


def setup_undo(args: argparse.Namespace) -> int:
    cfg = ssh_config_path()
    if cfg.exists() and SSH_CONFIG_BEGIN in cfg.read_text():
        if ask(f"Remove the sshelper block from {cfg}?", True, args.yes):
            cfg.write_text(strip_managed_block(cfg.read_text()).rstrip("\n") + "\n")
            print("[ok] removed ssh config block")
    if SYSCTL_FILE.exists():
        if ask(f"Remove {SYSCTL_FILE} and restore the default (1024)? (sudo)", True, args.yes):
            subprocess.run(["sudo", "rm", "-f", str(SYSCTL_FILE)])
            subprocess.run(["sudo", "sysctl", "-q", "-w", f"{SYSCTL_KEY}=1024"])
            print("[ok] removed sysctl setting")
    settings = load_settings()
    if settings["port"] < 1024:
        settings["port"] = DEFAULT_PORT
        save_settings(settings)
    info = daemon_info()
    if info:
        stop_daemon(info)
        print("[ok] daemon stopped")
    print("Existing ControlMaster sessions keep running until they close.")
    return 0


# -- doctor -------------------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    def line(label: str, value: str) -> None:
        print(f"{label:<14}{value}")

    line("sshelper", f"{__version__}  ({current_executable_path()})")
    line("python", f"{sys.version.split()[0]}  ({sys.executable})")
    try:
        ssh_version = subprocess.run(["ssh", "-V"], capture_output=True, text=True,
                                     timeout=5).stderr.strip()
    except OSError:
        ssh_version = "NOT FOUND"
    line("ssh", ssh_version)
    cfg = ssh_config_path()
    has_block = cfg.exists() and SSH_CONFIG_BEGIN in cfg.read_text()
    line("ssh config", "sshelper block present" if has_block else "block missing: run `sshelper setup`")
    settings = load_settings()
    control = ssh_g("sshelper-doctor.invalid").get("controlpath", "none")
    dirs = [str(Path(d).expanduser()) for d in settings["control_dirs"]]
    covered = any(control.startswith(d.rstrip("/") + "/") for d in dirs)
    line("ControlPath", f"{control}  " + ("ok" if covered else f"(not inside {', '.join(dirs)})"))
    tools = [name for name in ("ss", "lsof") if shutil.which(name)]
    line("tools", ", ".join(tools) or "neither ss nor lsof found: forwards cannot be listed")
    start = unprivileged_port_start()
    port = settings["port"]
    port_note = ""
    if port < 1024 and start is not None:
        port_note = (f"  ({SYSCTL_KEY}={start}: ok)" if start <= port
                     else f"  ({SYSCTL_KEY}={start}: run `sshelper setup --port {port}`)")
    line("port", f"{port}{port_note}")
    info = daemon_info()
    if info and daemon_ping(info):
        line("daemon", f"running, pid {info['pid']}, {dashboard_url(info['port'])}")
        try:
            state = api_call(info, "GET", "/api/state")
            line("connections", f"{len(state['connections'])} controllable, "
                                f"{len(state['uncontrolled'])} not controllable")
            for c in state["connections"]:
                line("", f"{c['dest']}: {conn_summary(c)}")
                if c["push"]["error"]:
                    line("", f"  push: {c['push']['error']}")
            if state.get("notice"):
                line("notice", state["notice"])
        except DaemonError as exc:
            line("connections", f"? ({exc})")
    else:
        line("daemon", "not running (starts automatically)")
    line("auto-update", "off" if auto_update_disabled() else "on (daily)")
    line("state", str(state_dir()))
    return 0


# ---------------------------------------------------------------------------
# self-update (same scheme as slurmctl)
# ---------------------------------------------------------------------------

AUTO_UPDATE_INTERVAL_SECONDS = 24 * 60 * 60
AUTO_UPDATE_DISABLE_ENV = "SSHELPER_NO_AUTO_UPDATE"
AUTO_UPDATE_COMMANDS = {None, "ls", "web", "doctor", "open", "close", "setup"}


def parse_version(value: str) -> tuple[int, ...] | None:
    text = value.strip().removeprefix("v")
    if not text:
        return None
    numbers = []
    for part in text.split("."):
        if not part.isdigit():
            return None
        numbers.append(int(part))
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers)


def read_url(url: str, *, timeout: float = 20.0) -> bytes:
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json, application/octet-stream",
        "User-Agent": f"sshelper/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


def latest_release_info() -> tuple[str, str]:
    api_url = os.environ.get("SSHELPER_UPDATE_API_URL", LATEST_RELEASE_API_URL)
    asset_url = os.environ.get("SSHELPER_UPDATE_ASSET_URL", LATEST_RELEASE_ASSET_URL)
    try:
        payload = json.loads(read_url(api_url).decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"failed to read latest release metadata: {exc}") from exc
    tag = str(payload.get("tag_name") or "").strip()
    if not tag:
        raise RuntimeError("latest release metadata did not include tag_name")
    for asset in payload.get("assets") or []:
        if asset.get("name") == RELEASE_ASSET_NAME and asset.get("browser_download_url"):
            asset_url = str(asset["browser_download_url"])
            break
    return tag, asset_url


def current_executable_path() -> Path:
    raw = sys.argv[0]
    found = shutil.which(raw) if os.sep not in raw else None
    return Path(found or raw).resolve()


def validate_downloaded_executable(path: Path, *, expected_version: str | None = None
                                   ) -> tuple[bool, str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return False, f"cannot read downloaded file: {exc}"
    if b"__version__" not in data or APP_MARKER.encode() not in data:
        return False, "downloaded file does not look like sshelper"
    proc = subprocess.run([sys.executable, str(path), "--version"], text=True,
                          capture_output=True, timeout=10)
    if proc.returncode != 0:
        return False, (proc.stdout + proc.stderr).strip() or "validation failed"
    if expected_version is not None:
        downloaded = proc.stdout.strip().split()[-1]
        if parse_version(downloaded) != parse_version(expected_version):
            return False, f"downloaded version {downloaded} does not match release {expected_version}"
    return True, ""


def write_update_candidate(target: Path, data: bytes) -> Path:
    fd, tmp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        mode = target.stat().st_mode if target.exists() else 0o755
        tmp_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return tmp_path
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def self_update_target() -> tuple[Path | None, str]:
    target = current_executable_path()
    if target.name.endswith(".py"):
        return None, f"refusing to self-update {target.name}; install the release asset as 'sshelper'"
    if not target.exists():
        return None, f"executable not found: {target}"
    if not os.access(target.parent, os.W_OK):
        return None, f"cannot write to {target.parent}"
    return target, ""


def install_release(target: Path, latest_tag: str, asset_url: str) -> tuple[bool, str]:
    try:
        data = read_url(asset_url)
        tmp_path = write_update_candidate(target, data)
        ok, reason = validate_downloaded_executable(tmp_path, expected_version=latest_tag)
        if not ok:
            tmp_path.unlink(missing_ok=True)
            return False, f"downloaded update failed validation: {reason}"
        os.replace(tmp_path, target)
    except (OSError, urllib.error.URLError, subprocess.SubprocessError) as exc:
        return False, f"update failed: {exc}"
    return True, ""


def update_state_path() -> Path:
    return config_dir() / "update-state.json"


def load_update_state() -> dict:
    state = read_json(update_state_path(), {})
    return state if isinstance(state, dict) else {}


def save_update_state(state: dict) -> None:
    try:
        write_json_atomic(update_state_path(), state)
    except OSError:
        pass


def auto_update_disabled() -> bool:
    return os.environ.get(AUTO_UPDATE_DISABLE_ENV, "").strip().lower() not in {"", "0", "false", "no"}


def maybe_start_background_update() -> None:
    if auto_update_disabled():
        return
    target, _ = self_update_target()
    if target is None:
        return
    state = load_update_state()
    now = time.time()
    try:
        last_check = float(state.get("last_check") or 0)
    except (TypeError, ValueError):
        last_check = 0.0
    if 0 <= now - last_check < AUTO_UPDATE_INTERVAL_SECONDS:
        return
    state["last_check"] = now
    save_update_state(state)
    try:
        subprocess.Popen([sys.executable, str(target), "update", "--background"],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                         env=dict(os.environ, **{AUTO_UPDATE_DISABLE_ENV: "1"}))
    except OSError:
        pass


def background_update() -> int:
    lock_path = update_state_path().with_name("update.lock")
    try:
        ensure_private_dir(lock_path.parent)
        lock_handle = lock_path.open("w")
    except OSError:
        return 1
    with lock_handle:
        try:
            fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return 0
        state = load_update_state()
        state["last_check"] = time.time()
        state.pop("last_error", None)
        try:
            latest_tag, asset_url = latest_release_info()
            latest, current = parse_version(latest_tag), parse_version(__version__)
            if latest is None:
                raise RuntimeError(f"latest release tag is not semver-like: {latest_tag}")
            if current is not None and latest <= current:
                save_update_state(state)
                return 0
            target, problem = self_update_target()
            if target is None:
                raise RuntimeError(problem)
            ok, reason = install_release(target, latest_tag, asset_url)
            if not ok:
                raise RuntimeError(reason)
        except RuntimeError as exc:
            state["last_error"] = str(exc)
            save_update_state(state)
            return 1
        state.update(updated_from=__version__, updated_to=latest_tag.lstrip("v"), notified=False)
        save_update_state(state)
        return 0


def take_update_notice() -> str:
    state = load_update_state()
    updated_to = state.get("updated_to")
    if not updated_to or state.get("notified"):
        return ""
    if parse_version(str(updated_to)) != parse_version(__version__):
        return ""
    state["notified"] = True
    save_update_state(state)
    return f"sshelper updated {state.get('updated_from') or '?'} -> {__version__}"


def cmd_update(args: argparse.Namespace) -> int:
    if args.background:
        return background_update()
    try:
        latest_tag, asset_url = latest_release_info()
    except RuntimeError as exc:
        print(f"sshelper: {exc}", file=sys.stderr)
        return 1
    current, latest = parse_version(__version__), parse_version(latest_tag)
    if latest is None:
        print(f"sshelper: latest release tag is not semver-like: {latest_tag}", file=sys.stderr)
        return 1
    print(f"current: {__version__}")
    print(f"latest:  {latest_tag}")
    newer = current is None or latest > current
    if args.check:
        print("update available" if newer else "sshelper is already up to date")
        return 1 if newer else 0
    if not newer and not args.force:
        print("sshelper is already up to date")
        return 0
    target, problem = self_update_target()
    if target is None:
        print(f"sshelper: {problem}", file=sys.stderr)
        return 2
    ok, reason = install_release(target, latest_tag, asset_url)
    if not ok:
        print(f"sshelper: {reason}", file=sys.stderr)
        return 1
    print(f"updated sshelper {__version__} -> {latest_tag}")
    print("the daemon restarts with the new version the next time you run sshelper")
    return 0


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sshelper",
        description=f"{APP_MARKER}. Run without arguments for the TUI.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    setup = sub.add_parser("setup", help="ssh ControlMaster block + dashboard port (run once)")
    setup.add_argument("--port", type=int, help="dashboard port (80 = no port in the URL, sudo once)")
    setup.add_argument("--undo", action="store_true", help="revert everything setup changed")
    setup.add_argument("-y", "--yes", action="store_true", help="do not ask")
    ls = sub.add_parser("ls", help="list connections, forwards and listening ports")
    ls.add_argument("--json", action="store_true")
    op = sub.add_parser("open", help="forward a remote port to the laptop")
    op.add_argument("host", help="connection (ssh alias, as in `sshelper ls`)")
    op.add_argument("spec", help="PORT, PORT:LOCAL, HOST:PORT or HOST:PORT:LOCAL")
    op.add_argument("--pin", action="store_true", help="reopen automatically when the host reconnects")
    op.add_argument("-b", "--browser", action="store_true", help="open it in the browser")
    cl = sub.add_parser("close", help="close a forward")
    cl.add_argument("host")
    cl.add_argument("port", nargs="?", type=int, help="local port")
    cl.add_argument("--all", action="store_true")
    web = sub.add_parser("web", help="open the dashboard")
    web.add_argument("project", nargs="?")
    ag = sub.add_parser("agent", help="agent skill on a host (Claude Code, Codex, ...) so its agents can push here")
    ag.add_argument("action", choices=["on", "off", "status"])
    ag.add_argument("host", nargs="?")
    dm = sub.add_parser("daemon", help="manage the background daemon")
    dm.add_argument("action", choices=["start", "stop", "restart", "status", "log", "run"])
    sub.add_parser("doctor", help="check the environment")
    up = sub.add_parser("update", help="update this executable")
    up.add_argument("--check", action="store_true", help="only check whether an update is available")
    up.add_argument("--force", action="store_true", help="reinstall even if up to date")
    up.add_argument("--background", action="store_true", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command in AUTO_UPDATE_COMMANDS:
        maybe_start_background_update()
        notice = take_update_notice()
        if notice:
            if args.command is None:
                args.startup_message = notice
            elif sys.stderr.isatty():
                print(notice, file=sys.stderr)
    handlers = {
        None: cmd_tui, "ls": cmd_ls, "open": cmd_open, "close": cmd_close, "web": cmd_web,
        "daemon": cmd_daemon, "agent": cmd_agent, "setup": cmd_setup, "doctor": cmd_doctor, "update": cmd_update,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
