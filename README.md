# sshelper

Port forwarding and remote file viewing for your ssh connections, from the
laptop. One Python file, standard library only, nothing installed on remotes.

- Open, close and pin `-L` port forwards on any live `ssh` connection, from a
  TUI or from the browser. Ports listening on the remote are detected for you.
- Anything on a remote machine (you, a script, a coding agent) can **push**
  files, videos, ports, notes and links to the laptop. They show up as boxes,
  grouped by project, at **http://ssh.localhost**.
- Files never get copied: the laptop streams them over your existing ssh
  connection when you look at them (video seeking, live `tail -f` included).

```
laptop                                              remote (robopc)
──────                                              ───────────────
ssh robopc  ────── one ControlMaster connection ──── sshd
   ▲                                                  │
sshelper daemon ◄── reverse port (push channel) ───── curl $SSHELPER_URL/push
   │                                                  (you, scripts, agents)
   ├── TUI (`sshelper`)
   └── http://ssh.localhost   boxes · forwards · file browser
```

## Requirements

- Laptop: Python 3.11+, OpenSSH 8.0+, `ss` (Linux) or `lsof`.
- Remotes: a POSIX shell, standard tools (`cat`, `stat`, `tail`, `find`),
  `ss` or `netstat` for port detection, `curl` (or Python) to push.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/pietrosig/sshelper/main/install.sh | sh
sshelper setup
```

Manual single-file install:

```bash
mkdir -p ~/.local/bin
curl -fsSL https://github.com/pietrosig/sshelper/releases/latest/download/sshelper -o ~/.local/bin/sshelper
chmod +x ~/.local/bin/sshelper
```

`sshelper setup` (run once):

1. Adds a managed block to `~/.ssh/config` so every `ssh host` uses a
   ControlMaster socket in `~/.ssh/cm/` that sshelper can control.
   Host-specific settings you already have keep priority; github/gitlab/
   bitbucket are excluded. A backup is written to `~/.ssh/config.sshelper-backup`.
2. Asks for the dashboard address:
   - `http://ssh.localhost` (port 80): one-time sudo, writes
     `/etc/sysctl.d/50-sshelper.conf` (`net.ipv4.ip_unprivileged_port_start=80`)
   - `http://ssh.localhost:9100`: no sudo.

   Non-interactive: `sshelper setup --port 80` or `--port 9100`.

`sshelper setup --undo` reverts both. Connections opened before setup are not
controllable until you reconnect.

## Use

Keep using plain `ssh host`. Then:

```bash
sshelper                         # TUI
sshelper ls                      # connections, forwards, listening ports
sshelper open robopc 8080        # remote 8080 -> localhost:8080
sshelper open robopc 8080:9000   # remote 8080 -> localhost:9000
sshelper open cluster gpu042:8888 --pin   # via the login node; reopen on reconnect
sshelper close robopc 8080       # or --all
sshelper web [project]           # open the dashboard
sshelper agent on|off|status [HOST]   # agent skill per remote (on by default)
sshelper doctor
```

The daemon starts automatically. `sshelper daemon start|stop|restart|status|log`
manages it by hand.

### TUI keys

`j`/`k` or arrows move, Enter opens/forwards, `b` back, `q` quit, `w` opens
the dashboard. On a host: `a` add forward, `d` close, `p` pin, `o` open in
browser, `r` rescan. On projects/boxes: `o` open in browser, `d` delete.

## Pushing from a remote

When a connection is detected, sshelper opens a reverse port on the remote and
writes into `~/.sshelper/` there:

- `README.md`: full instructions, written for agents (and humans)
- `push`: a helper that reads the current port and token by itself
- `hosts/<hostname>.env` / `.json`: port and token for raw HTTP

### Agent skill (Claude Code, Codex, ...)

On by default: on every connection sshelper installs a skill on the remote, so
every agent session there knows how to push. Turn it off for a host (this
removes the skill there) with:

```bash
sshelper agent off robopc     # or the "Agent skill" toggle in the TUI/dashboard
sshelper agent on robopc      # back on
sshelper agent status
```

It writes the same `SKILL.md` (rewritten on every connect) to:

- `~/.agents/skills/sshelper/`: the shared skills folder (Codex and other
  agents that use the shared layout)
- `~/.claude/skills/sshelper/`: Claude Code

Not `~/.codex/skills/`: Codex reads both folders and would list it twice. The
skill only loads when the agent has something to show. Agents without skill
support can read `~/.sshelper/README.md`.

A push (the agent picks `project`):

```bash
~/.sshelper/push '{
  "project": "my-experiment",
  "title":   "run 12 - pick cube",
  "sender":  "claude-agent",
  "items": [
    {"path": "/home/me/runs/12/cam0.mp4", "caption": "wrist cam"},
    {"path": "/home/me/runs/12/"},
    {"port": 8080, "name": "viser scene"},
    {"text": "success rate 7/10"},
    {"url": "https://wandb.ai/..."}
  ]}'
```

Exit codes: 0 pushed (or queued), 1 rejected (error printed), 2 could not deliver or queue.

Sandboxed agents (e.g. Codex, whose sandbox has no network, not even
`127.0.0.1`) cannot reach the push port. The helper then queues the push as a
file in `/tmp/sshelper-<uid>/inbox/` (a folder only you own) and prints
`"queued": true`; the laptop collects the inbox over ssh every couple of
seconds. Pushes queued while the laptop is offline arrive on the next connect.

Each box shows where it came from: the connection (verified: one listener
per connection) and the optional `sender` (self-reported).

Videos must be browser-playable: H.264 mp4 (OpenCV fourcc `avc1`) or webm.
OpenCV's `mp4v` does not play in browsers.

Why not `curl ssh.localhost` on the remote: that would need port 80 there
(root), and a fixed port could be held by another user on a shared machine.

## Security

- The push port lives on the remote's `127.0.0.1`, which other users of a
  shared machine can reach: every push needs the token (file mode 0600), and
  the push port only accepts requests. Nothing is ever sent back to the remote.
- The dashboard binds `127.0.0.1` only, accepts only `ssh.localhost` /
  `localhost` host names (DNS-rebinding protection), refuses cross-site
  requests, and requires a per-session token for every change.
- Remote files are served with a sandboxing CSP, so a remote HTML file cannot
  act on the dashboard.
- Assumes a single-user laptop: other local users could reach `127.0.0.1`.

## Files

| Where | What |
|---|---|
| `~/.config/sshelper/settings.json` | settings (`port`, `browser`, `push_channel`, `push_disabled_hosts`, `agent_skill_disabled_hosts`, `control_dirs`, retention) |
| `~/.local/state/sshelper/` | `pushes.jsonl`, `forwards.json` (pins), `daemon.json`, `daemon.log` |
| `~/.ssh/cm/` | ControlMaster sockets |
| remote `~/.sshelper/` | `README.md` (instructions), `push` (helper), `hosts/<hostname>.env/.json` (port + token) |
| remote `~/.agents/skills/sshelper/`, `~/.claude/skills/sshelper/` | agent skill (`SKILL.md`), unless turned off for that host |

## Updates

Same scheme as slurmctl: at most once a day a detached background check
installs a new release; the daemon is restarted on the new version the next
time you run `sshelper`. `sshelper update [--check]` updates by hand,
`SSHELPER_NO_AUTO_UPDATE=1` turns automatic updates off. A development
checkout (`sshelper.py`) never self-updates.

## Release

Push a `v*` tag matching `__version__`; the workflow publishes `sshelper.py`
as the release asset `sshelper`.
