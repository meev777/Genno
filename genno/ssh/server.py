"""Genno SSH engine: logs every auth attempt, policy decides when to let in."""
import asyncio, uuid, argparse
from pathlib import Path
import asyncssh
from genno.telemetry.sink import Sink

BANNER = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"

class Policy:
    """Accept after `after` failed attempts on one connection, or on an allowlist."""
    def __init__(self, after=3, allow=None):
        self.after = after
        self.allow = set(allow or [])
    def decide(self, user, pw, attempt_no):
        return (user, pw) in self.allow or attempt_no > self.after

class GennoServer(asyncssh.SSHServer):
    def __init__(self, sink, policy):
        self.sink, self.policy = sink, policy
        self.sid = uuid.uuid4().hex[:12]
        self.attempts = 0
        self.peer = ("?", 0)

    def connection_made(self, conn):
        self.conn = conn
        self.peer = conn.get_extra_info("peername")[:2]
        self.sink.emit("connect", self.sid, *self.peer)

    def connection_lost(self, exc):
        self.sink.emit("disconnect", self.sid, *self.peer, error=str(exc) if exc else None)

    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        self.attempts += 1
        ok = self.policy.decide(username, password, self.attempts)
        self.sink.emit("auth_attempt", self.sid, *self.peer, username=username,
                       password=password, success=ok, attempt=self.attempts,
                       client_version=self.conn.get_extra_info("client_version"))
        return ok

def make_process_factory(sink, sid_of):
    async def handle(process):
        srv = process.get_extra_info("genno")  # set below
        sid, peer = srv.sid, srv.peer
        user = process.get_extra_info("username")
        async def run(cmd):
            sink.emit("command", sid, *peer, username=user, command=cmd)
            name = cmd.split()[0] if cmd.split() else ""
            if name in ("exit", "logout"):
                return True
            if name:
                process.stdout.write(f"bash: {name}: command not found\n")
            return False
        if process.command is not None:
            await run(process.command)
            process.exit(0)
            return
        process.stdout.write("Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n\n")
        while True:
            process.stdout.write(f"{user}@srv01:~$ ")
            try:
                line = await process.stdin.readline()
            except asyncssh.BreakReceived:
                break
            if not line:
                break
            if await run(line.strip()):
                break
        process.exit(0)
    return handle

async def start(host="127.0.0.1", port=2222, logfile="data/events.jsonl",
                keyfile="data/host_ed25519", policy=None):
    sink = Sink(logfile)
    policy = policy or Policy()
    kf = Path(keyfile)
    if not kf.exists():
        kf.parent.mkdir(parents=True, exist_ok=True)
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(kf))
    servers = {}

    def factory():
        s = GennoServer(sink, policy)
        servers[s.sid] = s
        return s

    inner = make_process_factory(sink, None)
    async def process_factory(process):
        conn = process.channel.get_connection()
        srv = next((s for s in servers.values() if s.conn is conn), None)
        orig = process.get_extra_info
        process.get_extra_info = lambda k, d=None: srv if k == "genno" else orig(k, d)
        await inner(process)

    return await asyncssh.listen(
        host, port, server_factory=factory, server_host_keys=[str(kf)],
        process_factory=process_factory, server_version=BANNER,
        line_editor=True, encoding="utf-8")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--log", default="data/events.jsonl")
    a = ap.parse_args()
    loop = asyncio.new_event_loop()
    loop.run_until_complete(start(a.host, a.port, a.log))
    print(f"genno ssh listening on {a.host}:{a.port}")
    loop.run_forever()

if __name__ == "__main__":
    main()
