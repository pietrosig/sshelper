# sshelper — v1 spec (draft for review)

## 1. Goal

Make ssh port forwarding and "show me that remote stuff" effortless, from the
laptop, without mounting anything and without installing anything on remotes.

- Open / close / change port forwards on any live ssh connection, from a TUI or
  from the browser.
- Anything on a remote machine (you, a script, a coding agent) can **push**
  files, ports, text or links to the laptop, and they show up as project boxes
  at **http://ssh.localhost**.

Example: laptop → `ssh robopc`. Forward 8080 and 8081 (two viser instances).
The coding agent on robopc is told "use sshelper": it runs
`curl localhost:<port>`, reads the instructions, records videos, pushes them.
The videos appear in the `grasping` box on the laptop, playable in Chrome.

### Non-goals (v1)

- Editing remote code (use VS Code Remote / nvim over ssh).
- Copying files to the laptop (browser cache only).
- Anything installed or left running on the remote.
- Windows. macOS is best-effort; Linux is the target.

## 2. Packaging

Same as slurmctl:

- One file, `sshelper.py`, Python 3.11+, standard library only.
- Polyglot `sh`/Python first line that picks a Python 3.11+ interpreter
  (`SSHELPER_PYTHON` override).
- GitHub release asset `sshelper` on `v*` tags, `install.sh` to
  `~/.local/bin`, `sshelper update`, daily background auto-update
  (`SSHELPER_NO_AUTO_UPDATE=1` to disable).

Requirements on the laptop: Python 3.11+, OpenSSH 8.0+, `ss` (or `lsof`).
Requirements on remotes: a POSIX shell, `ls`/`cat`/`stat`/`tail`, `ss` or
`netstat` for port detection, `curl` for pushing.

## 3. Architecture

```
            ┌── TUI (sshelper)
daemon ◄────┤                          one process on the laptop, single source of truth
(state)     └── browser (http://ssh.localhost)

daemon ──ssh -O / ssh -S──► existing ControlMaster connections ──► remotes
```

- **Daemon**: background process on the laptop. Started automatically by any
  `sshelper` command if it is not running (detached, guarded by a lock file).
  Holds all state, talks to ssh, serves the dashboard and the push endpoints.
- **TUI and browser** are both clients of the daemon's local API (§8). A change
  in one appears in the other immediately.
- **No wrapper around ssh.** You keep typing `ssh host`. sshelper finds your
  connections through ControlMaster sockets.

## 4. Setup (`sshelper setup`)

Idempotent, shows what it will change and asks before each step.
`sshelper setup --undo` reverts everything.

1. **ssh config**: appends a managed block to `~/.ssh/config`:
   ```
   # >>> sshelper managed >>>
   Host *
       ControlMaster auto
       ControlPath ~/.ssh/cm/%C
       ControlPersist 10m
   # <<< sshelper managed <<<
   ```
   Creates `~/.ssh/cm/` with mode 0700. Because ssh config is first-match-wins,
   host-specific settings the user already has keep priority; the daemon
   resolves each host's real control path with `ssh -G host`.
2. **Dashboard address** — setup asks which one you want:
   - **No port** (one-time sudo): writes `/etc/sysctl.d/50-sshelper.conf` with
     `net.ipv4.ip_unprivileged_port_start=80` and applies it, so the daemon
     serves `http://ssh.localhost`.
   - **Plain port, no sudo**: the daemon serves `http://ssh.localhost:9100`
     (or any port you choose). Nothing outside your home directory is touched.

   Non-interactive: `sshelper setup --port 80` or `sshelper setup --port 9100`
   (any port ≥ 1024 never needs sudo). The choice is stored as `"port"` in
   settings and can be changed later in the TUI/browser settings or by
   re-running setup. If port 80 is chosen but unavailable (sysctl not applied,
   or something else is listening), the daemon falls back to 9100 and every UI
   shows the actual address.

Connections opened before setup have no control socket; the TUI lists them as
"not controllable — reconnect".

## 5. Connections

- The daemon scans control sockets every 2 s and runs `ssh -O check` on each.
- Per connection it knows: ssh alias, real hostname/IP (`ssh -G`), remote
  user, remote `hostname`, master pid, status.
- Status values: `ok`, `forwarding blocked` (server refuses `-L`/`-R`),
  `not controllable`, `gone`.
- If forwarding is blocked, it is shown in the TUI and the browser; nothing else
  breaks.

## 6. Forwards (laptop ← remote, `-L`)

- **Open**: `ssh -S <sock> -O forward -L <local>:<target>:<port> host`.
  - Target is `localhost` by default, or a node name (`gpu042:8888`) to reach a
    machine behind the remote (cluster compute nodes).
  - Local port defaults to the remote port; if busy, the next free port is used
    and shown.
- **Close**: `ssh -O cancel -L …`.
- **List active**: local listening sockets owned by the master pid
  (`ss -tlnpH`), so forwards not made by sshelper show up too.
- **Detect remote ports**: `ss -tlnpH` over the connection (fallback
  `netstat`), only the user's own processes, shown with the process name
  (`8080 python (viser)`). One click / key to forward.
- **Pinned forwards**: a forward can be pinned per host; when that host
  reconnects, pinned forwards are reopened automatically.

## 7. Push channel (remote → laptop, `-R`)

### 7.1 Wiring

For every controllable connection (unless disabled per host):

1. The daemon opens a dedicated laptop-side listener on `127.0.0.1:<random>`.
   One listener per connection ⇒ the daemon knows for sure which connection a
   push came from.
2. `ssh -O forward -R 0:127.0.0.1:<that port> host`; the remote picks a free
   port and ssh reports it.
3. The daemon writes `~/.sshelper/hosts/<remote hostname>.json` on the remote
   (dir 0700, file 0600):
   ```json
   {"port": 41733, "token": "9f2c…", "laptop": "pietro-laptop"}
   ```
   Keyed by remote hostname because cluster login nodes share `$HOME`.
4. On disconnect the forward disappears; the file is removed on clean shutdown,
   and stale files are harmless (the port is closed).

### 7.2 Endpoints (the only thing the remote can reach)

The remote-facing endpoints **never return file contents or laptop state**.
They only accept requests.

| Method | Path | Token | What |
|---|---|---|---|
| GET | `/` | no | plain-text instructions written for agents and humans |
| POST | `/push` | yes | push a box (JSON, below) |
| GET | `/push?project=…&path=…&title=…` | yes | short form for one item |
| GET | `/ping` | yes | `{"ok": true, "laptop": "…"}` to check the link |

Token goes in the `X-Token` header (or `token=` query param for the short form).
Body limit 64 KB.

### 7.3 Push format

```json
{
  "project": "grasping",
  "title":   "run 12 – pick cube",
  "sender":  "claude-agent",
  "items": [
    {"path": "/home/me/runs/12/cam0.mp4", "caption": "wrist cam"},
    {"path": "/home/me/runs/12/"},
    {"port": 8080, "name": "viser scene"},
    {"text": "success rate 7/10"},
    {"url": "https://wandb.ai/…"}
  ]
}
```

- `project`: required, `[a-z0-9-_]`, becomes `ssh.localhost/<project>`.
- `title`, `sender`: optional. `sender` is self-reported and shown as such.
- `path`: absolute, file or directory, stays on the remote; streamed on demand.
- `port`: a port on that remote; the box shows a link, and an "open forward"
  button if it is not forwarded yet.
- Response: `{"ok": true, "id": "…", "url": "http://ssh.localhost/grasping#…"}`.

### 7.4 What `GET /` says

Short, copy-pasteable, agent-friendly:

- what sshelper is and which laptop is connected,
- how to read port and token:
  `cat ~/.sshelper/hosts/$(hostname).json`,
- the push format with one full `curl` example,
- rules: absolute paths, one box per logical result, videos should be H.264
  (`avc1`) mp4 or webm — OpenCV's `mp4v` does not play in browsers.

## 8. Dashboard and local API (laptop only)

Listens on `127.0.0.1:<port>` from settings (80 or e.g. 9100). Accepts only `Host` =
`ssh.localhost` / `localhost` / `127.0.0.1` (blocks DNS rebinding).

### 8.1 Pages

- `/` — **connections panel** (each host: status, forwards with
  open/close/edit, detected ports, pinned toggles) and **project boxes**,
  newest first.
- `/<project>` — one project's boxes.
- `/f/<connection>/<absolute path>` — file or directory view:
  - directory → listing (one `ls`-style command over ssh),
  - file → streamed with the right content type and HTTP Range support
    (video seeking), via `ssh -S … cat` / ranged reads,
  - `.log`/`.txt` → optional live tail view.
- Live updates via Server-Sent Events.

### 8.2 Box

```
grasping · run 12 – pick cube                                   14:32
from robopc (192.168.1.42, user pietro) · via claude-agent
[ video ][ video ]  wrist cam
📁 /home/me/runs/12/   ·   viser scene → localhost:8080 ●   ·   success rate 7/10
```

"from …" is verified (which connection); "via …" is self-reported. Files of a
disconnected host show "offline"; anything still in the browser cache keeps
working.

### 8.3 Caching

File URLs include `?v=<mtime>-<size>` and are served
`Cache-Control: private, max-age=31536000, immutable`, so anything already
viewed reloads from cache. Videos loaded in ranges may still not replay
offline (no copying in v1).

### 8.4 Local API (used by the TUI and the dashboard)

JSON under `/api/`: connections, forwards (open/close/edit/pin), detected
ports, pushes (list/delete), settings. Every request that changes something
requires the session token (embedded in the page; the TUI reads it from the
state dir) and a matching `Origin`.

## 9. TUI (`sshelper`)

Same look and keys as slurmctl (j/k, Enter, Tab search, B back, q quit).

- **Connections** — host, status, number of forwards.
- **Host** — active forwards, detected ports, pinned; keys: `a` add, `d`
  close, `e` edit local port, `p` pin, `o` open in browser.
- **Pushes** — projects → boxes → items; Enter opens the item in the browser.
- **Settings** — dashboard port, browser command, push channel on/off per host, retention.

## 10. CLI

```
sshelper                         TUI
sshelper setup [--port N] [--undo]   ssh config block + dashboard port (80 = sudo once)
sshelper ls                      connections and forwards
sshelper open HOST PORT[:LOCAL]
sshelper open HOST NODE:PORT[:LOCAL]
sshelper close HOST PORT | --all
sshelper web                     open http://ssh.localhost
sshelper daemon start|stop|status
sshelper doctor                  ssh version, setup state, port 80, connections
sshelper update [--check]
sshelper --version
```

## 11. Files

| Where | What |
|---|---|
| `~/.config/sshelper/settings.json` | settings (`port`, browser command, per-host push channel, retention) |
| `~/.local/state/sshelper/` | `pushes.jsonl`, `forwards.json` (pins), `session.token`, `daemon.log`, `daemon.lock`, `update-state.json` |
| `~/.ssh/cm/` | control sockets |
| remote `~/.sshelper/hosts/<hostname>.json` | port + token for pushers |

Push retention: last 1000 boxes or 60 days, configurable.

## 12. Security summary

- Remote-side: per-connection port on remote `127.0.0.1` (reachable by other
  users on shared machines) ⇒ token required, endpoints are write-only, no
  data ever flows back to the remote.
- Laptop-side: binds `127.0.0.1` only, strict `Host` check, session token +
  `Origin` check for anything that changes state.
- Files are read with your own ssh session; nothing listens on the remote
  besides the ssh-managed `-R` port.

## 13. Later (not v1)

- `"copy": true` to cache pushed files on the laptop.
- Upload / drag-and-drop to the remote.
- Compute-node pushes via an inbox folder in a shared `$HOME`.
- `GET /client.sh` so remotes get a `sshelper push …` shell helper.
- ffmpeg transcode for unplayable videos.
- Desktop notifications (`notify` items).

## 14. Decisions taken during implementation (v0.1.0)

1. The push channel is on for every connection by default; turn it off
   globally (settings `push_channel`) or per host (`push_disabled_hosts`).
2. Detected ports are shown, never forwarded automatically; pinned forwards
   are reopened automatically on reconnect.
3. Names: `sshelper`, `http://ssh.localhost`.
4. Remote endpoint files also come as a shell-sourceable `.env`
   (`SSHELPER_URL`, `SSHELPER_TOKEN`, ...) next to the `.json`, plus a
   `~/.sshelper/README.txt` pointer, so agents can find the instructions.
5. Server-side forwarding policy is read from the remote's global
   `sshd_config` when readable, and from the `-R` result.
