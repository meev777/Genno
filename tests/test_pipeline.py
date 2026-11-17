"""End to end: simulated attackers -> real server -> JSONL -> SQLite -> classifier -> scored vs ground truth."""
import json
from genno.ssh.server import start, Policy
from tools.simulate import run_campaign, DEMO_ALLOW
from analysis.run import run
from analysis.classifier import Thresholds

COUNTS = {"scanner": 2, "brute_force": 1, "recon_bot": 3, "malware_dropper": 3,
          "cryptominer": 1, "persistence": 1, "human": 1}


async def test_full_pipeline_matches_ground_truth(tmp_path):
    log = tmp_path / "e.jsonl"
    srv = await start(port=0, logfile=str(log), keyfile=str(tmp_path / "k"), policy=Policy(after=3, allow=DEMO_ALLOW))
    port = srv.sockets[0].getsockname()[1]
    truth, fails = await run_campaign(port=port, seed=7, scale=0.15, counts=COUNTS)
    srv.close(); await srv.wait_closed()
    assert fails == []
    (tmp_path / "t.json").write_text(json.dumps(truth))
    res = run(str(log), str(tmp_path / "g.db"), layer=str(tmp_path / "layer.json"),
              truth=str(tmp_path / "t.json"), th=Thresholds(human_gap=0.1), out=open(tmp_path / "out.txt", "w"))
    assert res["accuracy"] == 1.0, open(tmp_path / "out.txt").read()
    labels = {l["label"] for l in res["labels"].values()}
    assert labels == set(COUNTS)
    layer = json.load(open(tmp_path / "layer.json"))
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1110.001", "T1078", "T1105", "T1098.004", "T1496", "T1082", "T1070.004"} <= ids
