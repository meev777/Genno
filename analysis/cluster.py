"""Unsupervised cross-check of the rule classifier: cluster sessions by command sequence.

Each session's commands are normalized (URLs/IPs/numbers abstracted, so only behaviour remains),
turned into word 1-3-grams, TF-IDF weighted and clustered with DBSCAN (cosine distance, no k to guess;
sessions that fit no cluster are noise). Sessions with no commands (scanners, brute force) are excluded.
"""
import argparse, re
from collections import Counter
from sklearn.cluster import DBSCAN
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import adjusted_rand_score, silhouette_score
from analysis.classifier import simple_commands

_URL = re.compile(r"^[a-z]+://\S+$|^\S+\.(test|com|net|org|ru|cn)(/\S*)?$", re.I)
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?(/\S*)?$")


def normalize_word(w):
    if _URL.match(w) or _IP.match(w):
        return "<URL>"
    if re.fullmatch(r"\d+", w):
        return "<N>"
    return w


def session_tokens(s):
    toks = []
    for _, cmd, _ in s["commands"]:
        for sc in simple_commands(cmd):
            toks += [sc[0]] + [normalize_word(w) for w in sc[1:]] + [";"]
    return toks


def cluster_sessions(sessions, eps=0.35, min_samples=2, ngram=(1, 3)):
    """-> (kept_sessions, cluster_ids, tfidf_matrix_or_None)  (cluster id -1 = noise)"""
    kept = [s for s in sessions if s["commands"]]
    if len(kept) < min_samples:
        return kept, [-1] * len(kept), None
    docs = [" ".join(session_tokens(s)) for s in kept]
    X = TfidfVectorizer(ngram_range=ngram, token_pattern=r"\S+", lowercase=False).fit_transform(docs)
    ids = DBSCAN(eps=eps, min_samples=min_samples, metric="cosine").fit_predict(X)
    return kept, [int(i) for i in ids], X


def report(sessions, labels=None, eps=0.35, out=print):
    kept, ids, X = cluster_sessions(sessions, eps=eps)
    n_clusters = len(set(ids) - {-1})
    out(f"sessions with commands: {len(kept)}   clusters: {n_clusters}   noise: {ids.count(-1)}   eps={eps}")
    if X is not None and n_clusters > 1 and len(set(ids)) < len(kept):
        mask = [i != -1 for i in ids]
        try:
            out(f"silhouette (non-noise): {silhouette_score(X[mask], [i for i in ids if i != -1], metric='cosine'):.3f}")
        except ValueError:
            pass
    for cid in sorted(set(ids)):
        members = [s for s, i in zip(kept, ids) if i == cid]
        name = "noise" if cid == -1 else f"cluster {cid}"
        rule = Counter((labels or {}).get(s["session_id"], {}).get("label", "?") for s in members)
        top = Counter(t for s in members for t in session_tokens(s) if t != ";").most_common(4)
        out(f"  {name:<10} n={len(members):<3} rule labels={dict(rule)}  top tokens={[t for t, _ in top]}")
    ari = None
    if labels and kept:
        ari = adjusted_rand_score([labels[s["session_id"]]["label"] for s in kept], ids)
        out(f"adjusted Rand index vs rule labels: {ari:.3f}  (1.0 = identical partition)")
    return kept, ids, ari


def main():
    from genno.telemetry.ingest import load_sessions
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/genno.db")
    ap.add_argument("--eps", type=float, default=0.35)
    a = ap.parse_args()
    sessions = load_sessions(a.db)
    labels = {s["session_id"]: {"label": s["label"]} for s in sessions if s["label"]}
    report(sessions, labels or None, a.eps)

if __name__ == "__main__":
    main()
