import json, asyncio, pytest, asyncssh
from tarpit.ssh.server import start, Policy

async def _client(port, user, pw):
    return await asyncssh.connect("127.0.0.1", port, username=user, password=pw,
                                  known_hosts=None, client_keys=None, agent_path=None)

def events(p):
    return [json.loads(l) for l in open(p)]

@pytest.mark.asyncio
async def test_auth_policy_and_exec(tmp_path):
    log = tmp_path / "e.jsonl"
    srv = await start(port=0, logfile=str(log), keyfile=str(tmp_path / "k"),
                      policy=Policy(after=2, allow=[("root", "toor")]))
    port = srv.sockets[0].getsockname()[1]
    # allowlisted creds get in immediately
    async with await _client(port, "root", "toor") as c:
        r = await c.run("whoami")
        assert "command not found" in r.stdout
    # failure then threshold acceptance
    with pytest.raises(asyncssh.PermissionDenied):
        await _client(port, "admin", "admin")
    srv.close(); await srv.wait_closed()
    ev = events(log)
    types = [e["event_type"] for e in ev]
    assert "connect" in types and "command" in types
    auths = [e for e in ev if e["event_type"] == "auth_attempt"]
    assert any(a["success"] and a["username"] == "root" for a in auths)
    assert any(not a["success"] and a["username"] == "admin" for a in auths)
    assert next(e for e in ev if e["event_type"] == "command")["command"] == "whoami"

@pytest.mark.asyncio
async def test_interactive_shell(tmp_path):
    log = tmp_path / "e.jsonl"
    srv = await start(port=0, logfile=str(log), keyfile=str(tmp_path / "k"),
                      policy=Policy(allow=[("a", "b")]))
    port = srv.sockets[0].getsockname()[1]
    async with await _client(port, "a", "b") as c:
        p = await c.create_process(term_type="xterm")
        p.stdin.write("ls\nexit\n")
        await asyncio.wait_for(p.wait(), 5)
    srv.close(); await srv.wait_closed()
    cmds = [e["command"] for e in events(log) if e["event_type"] == "command"]
    assert cmds == ["ls", "exit"]
