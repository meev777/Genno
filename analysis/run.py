"""python -m analysis.run --log data/events.jsonl --db data/genno.db [--truth data/sim_truth.json]"""
import argparse, json, sys
from collections import Counter
from genno.telemetry.ingest import ingest, load_sessions, save_labels
from analysis.classifier import Thresholds, classify_all, simple_commands
from analysis.attack_map import TECHNIQUES, export_navigator


def evaluate(sessions, labels, truth):
    ok, bad = 0, []
    for s in sessions:
        exp = truth.get(s["src_ip"])
        if exp is None:
            continue
        got = labels[s["session_id"]]["label"]
        if got == exp: ok += 1
        else: bad.append((s["src_ip"], exp, got))
    return ok, bad


def run(log, db, layer=None, truth=None, th=None, out=sys.stdout):
    n = ingest(log, db)
    sessions = load_sessions(db)
    labels = classify_all(sessions, th)
    save_labels(db, labels)
    p = lambda *a: print(*a, file=out)
    p(f"sessions: {n}   logged in: {sum(s['login_success'] for s in sessions)}")
    p("\n== labels")
    for k, v in Counter(l["label"] for l in labels.values()).most_common():
        p(f"  {k:<18}{v}")
    cred = Counter((c[0], c[1]) for s in sessions for c in s["creds"])
    p("\n== top credentials")
    for (u, pw), v in cred.most_common(5): p(f"  {v:>3}  {u}:{pw}")
    bins = Counter(sc[0] for s in sessions for c in s["commands"] for sc in simple_commands(c[1]))
    p("\n== top commands")
    for b, v in bins.most_common(8): p(f"  {v:>3}  {b}")
    tech = Counter(t for l in labels.values() for t in l["techniques"])
    p("\n== ATT&CK techniques (sessions)")
    for t, v in sorted(tech.items(), key=lambda x: -x[1]): p(f"  {v:>3}  {t}  {TECHNIQUES[t][0]}")
    if layer:
        export_navigator([l["techniques"] for l in labels.values()], layer)
        p(f"\nnavigator layer -> {layer}")
    result = {"sessions": sessions, "labels": labels}
    if truth:
        ok, bad = evaluate(sessions, labels, json.load(open(truth)))
        tot = ok + len(bad)
        p(f"\n== accuracy vs simulator ground truth: {ok}/{tot} = {ok / max(tot, 1):.1%}")
        for ip, exp, got in bad: p(f"  MISS {ip}: expected {exp}, got {got}")
        result["accuracy"] = ok / max(tot, 1)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="data/events.jsonl")
    ap.add_argument("--db", default="data/genno.db")
    ap.add_argument("--layer", default="reports/attack-layer.json")
    ap.add_argument("--truth")
    ap.add_argument("--human-gap", type=float, default=1.0)
    a = ap.parse_args()
    run(a.log, a.db, a.layer, a.truth, Thresholds(human_gap=a.human_gap))

if __name__ == "__main__":
    main()
