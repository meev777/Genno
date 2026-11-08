"""Genno SSH engine: logs every auth attempt, a policy decides when to let in, then an emulated shell."""
import asyncio, uuid, argparse
from pathlib import Path
import asyncssh
from genno.shell.profile import load_profile
from genno.shell.shell import Shell
from genno.telemetry.sink import Sink

BANNER = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
IDLE_TIMEOUT = 120


class Policy:
    """Accept after `after` failed attempts on one connection, or on an allowlist."""
    def __init__(self, after=3, allow=None):
        self.after = after
        self.allow = set(allow or [])
    def decide(self, user, pw, attempt_no):
        return (user, pw) in self.allow or attempt_no > self.after


class GennoServer(asyncssh.SSHServer):
    def __init__(self, sink, policy, profile, idle_timeout=IDLE_TIMEOUT, registry=None):
        self.sink, self.policy, self.profile = sink, policy, profile
        self.registry = registry if registry is not None else {}
        self.idle_timeout = idle_timeout
        self.sid = uuid.uuid4().hex[:12]
        self.attempts = 0
        self.peer = ("?", 0)

    def _emit(self, event_type, **fields):
        return self.sink.emit(event_type, self.sid, *self.peer, **fields)

    def connection_made(self, conn):
        self.conn = conn
        self.peer = conn.get_extra_info("peername")[:2]
        self.registry[conn] = self
        self._emit("connect")

    def connection_lost(self, exc):
        self.registry.pop(self.conn, None)
        self._emit("disconnect", error=str(exc) if exc else None)

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.attempts += 1
        ok = self.policy.decide(username, password, self.attempts)
        self._emit("auth_attempt", username=username, password=password, success=ok,
                   attempt=self.attempts, client_version=self.conn.get_extra_info("client_version"))
        return ok

    async def _handle(self, process):
        user = process.get_extra_info("username")
        tty = process.get_terminal_type() is not None
        sh = Shell(self.profile, user, emit=self._emit, tty=tty)

        if process.command is not None:
            self._emit("command", username=user, command=process.command, mode="exec")
            process.stdout.write(sh.run(process.command))
            process.exit(sh.last_rc & 0xFF)
            return

        self._emit("shell_open", username=user, term=process.get_terminal_type())
        process.stdout.write(self.profile["os_banner"] + "\n\n")
        while not sh.exited:
            process.stdout.write(sh.prompt())
            try:
                line = await asyncio.wait_for(process.stdin.readline(), self.idle_timeout)
            except asyncssh.TerminalSizeChanged:
                continue
            except (asyncssh.BreakReceived, asyncssh.SignalReceived):
                process.stdout.write("^C\n")
                continue
            except (asyncio.TimeoutError, asyncssh.Error):
                break
            if not line:
                break
            cmd = line.strip()
            if not cmd:
                continue
            self._emit("command", username=user, command=cmd, mode="shell")
            process.stdout.write(sh.run(cmd))
        if tty:
            process.stdout.write("logout\n")
        process.exit(0)


async def start(host="127.0.0.1", port=2222, logfile="data/events.jsonl",
                keyfile="data/host_ed25519", policy=None, profile="ubuntu-web",
                idle_timeout=IDLE_TIMEOUT):
    sink = Sink(logfile)
    policy = policy or Policy()
    prof = load_profile(profile)
    kf = Path(keyfile)
    if not kf.exists():
        kf.parent.mkdir(parents=True, exist_ok=True)
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(kf))
    registry = {}   # connection -> GennoServer, so the process handler can find per-connection state

    async def process_factory(process):
        srv = registry.get(process.channel.get_connection())
        if srv is not None:
            await srv._handle(process)

    return await asyncssh.listen(
        host, port, server_factory=lambda: GennoServer(sink, policy, prof, idle_timeout, registry),
        process_factory=process_factory, server_host_keys=[str(kf)], server_version=BANNER,
        line_editor=True, encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--log", default="data/events.jsonl")
    ap.add_argument("--key", default="data/host_ed25519")
    ap.add_argument("--profile", default="ubuntu-web")
    ap.add_argument("--after", type=int, default=3, help="accept after N failed attempts")
    a = ap.parse_args()
    loop = asyncio.new_event_loop()
    loop.run_until_complete(start(a.host, a.port, a.log, a.key, Policy(after=a.after), a.profile))
    print(f"genno ssh listening on {a.host}:{a.port}", flush=True)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
