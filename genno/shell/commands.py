"""Emulated commands: fn(sh, args, stdin) -> (stdout, stderr, rc). Nothing here executes anything real."""
import re, time
from urllib.parse import urlsplit

from .vfs import normalize


def split_args(args):
    """-> (single-letter flags, positionals). '--x' options are ignored; '--' ends flags."""
    flags, pos, done = set(), [], False
    for a in args:
        if done or a == "-" or not a.startswith("-"):
            pos.append(a)
        elif a == "--":
            done = True
        elif not a.startswith("--"):
            flags |= set(a[1:])
    return flags, pos


def fmt_mode(n):
    s = "d" if n.kind == "d" else "-"
    for shift in (6, 3, 0):
        b = (n.mode >> shift) & 7
        s += ("r" if b & 4 else "-") + ("w" if b & 2 else "-") + ("x" if b & 1 else "-")
    return s


def can_read(sh, n):
    if sh.uid == 0:
        return True
    return bool(n.mode & (0o400 if n.owner == sh.user else 0o004))


# ---------------------------------------------------------------- filesystem
def cmd_pwd(sh, args, stdin):
    return sh.cwd + "\n", "", 0


def cmd_cd(sh, args, stdin):
    _, pos = split_args(args)
    target = pos[0] if pos else "~"
    if target == "-":
        target = sh.oldpwd
    p = sh.path(target)
    n = sh.fs.get(p)
    if n is None:
        return "", f"bash: cd: {target}: No such file or directory\n", 1
    if n.kind != "d":
        return "", f"bash: cd: {target}: Not a directory\n", 1
    sh.oldpwd, sh.cwd = sh.cwd, p
    return "", "", 0


def _entry_line(name, n, w):
    return (f"{fmt_mode(n)} {w['links']:>{w['lw']}} {n.owner:<{w['ow']}} {n.owner:<{w['ow']}} "
            f"{_size(n):>{w['sw']}} {n.mtime} {name}")


def _size(n):
    return 4096 if n.kind == "d" else len(n.content)


def _links(sh, path, n):
    if n.kind != "d":
        return 1
    return 2 + sum(1 for c in sh.fs.listdir(path) if sh.fs.isdir(path.rstrip("/") + "/" + c))


def _render(sh, entries, long):
    """entries: [(display_name, abs_path, node)] -> text"""
    if not entries:
        return ""
    if not long:
        names = [e[0] for e in entries]
        if not sh.tty:
            return "\n".join(names) + "\n"
        lines, line = [], ""
        for nm in names:
            if line and len(line) + len(nm) + 2 > 80:
                lines.append(line); line = nm
            else:
                line = f"{line}  {nm}" if line else nm
        lines.append(line)
        return "\n".join(lines) + "\n"
    rows = [(nm, _links(sh, p, n), n) for nm, p, n in entries]
    w = {"lw": max(len(str(r[1])) for r in rows), "ow": max(len(r[2].owner) for r in rows),
         "sw": max(len(str(_size(r[2]))) for r in rows)}
    return "".join(_entry_line(nm, n, {**w, "links": lk}) + "\n" for nm, lk, n in rows)


def cmd_ls(sh, args, stdin):
    flags, pos = split_args(args)
    long, hidden = "l" in flags, bool(flags & {"a", "A"})
    out, err, rc, files, dirs = [], [], 0, [], []
    for p in pos or ["."]:
        ap = sh.path(p)
        n = sh.fs.get(ap)
        if n is None:
            err.append(f"ls: cannot access '{p}': No such file or directory\n"); rc = 2
        elif n.kind == "d":
            dirs.append((p, ap))
        else:
            files.append((p, ap, n))
    if files:
        out.append(_render(sh, sorted(files), long))
    for idx, (p, ap) in enumerate(sorted(dirs)):
        if len(pos) > 1:
            out.append(("\n" if out else "") + f"{p}:\n")
        names = [c for c in sh.fs.listdir(ap) if hidden or not c.startswith(".")]
        entries = []
        if "a" in flags:
            entries += [(".", ap, sh.fs.get(ap)), ("..", ap, sh.fs.get(ap))]
        entries += [(c, ap.rstrip("/") + "/" + c, sh.fs.get(ap.rstrip("/") + "/" + c)) for c in names]
        if long:
            total = sum(4 if e[2].kind == "d" else -(-len(e[2].content) // 4096) * 4 for e in entries)
            out.append(f"total {total}\n")
        out.append(_render(sh, entries, long))
    return "".join(out), "".join(err), rc


def cmd_cat(sh, args, stdin):
    _, pos = split_args(args)
    if not pos:
        return stdin, "", 0
    out, err, rc = [], [], 0
    for a in pos:
        if a == "-":
            out.append(stdin); continue
        ap = sh.path(a)
        n = sh.fs.get(ap)
        if n is None:
            err.append(f"cat: {a}: No such file or directory\n"); rc = 1
        elif n.kind == "d":
            err.append(f"cat: {a}: Is a directory\n"); rc = 1
        elif not can_read(sh, n):
            err.append(f"cat: {a}: Permission denied\n"); rc = 1
        else:
            sh.emit("file_read", path=ap)
            out.append(n.content)
    return "".join(out), "".join(err), rc


def cmd_touch(sh, args, stdin):
    _, pos = split_args(args)
    err, rc = [], 0
    for a in pos:
        ap = sh.path(a)
        if sh.fs.isfile(ap):
            e = sh.fs.write(ap, sh.fs.get(ap).content)
        else:
            e = sh.fs.write(ap, "", owner=sh.user)
        if e:
            err.append(f"touch: cannot touch '{a}': {e}\n"); rc = 1
    return "", "".join(err), rc


def cmd_mkdir(sh, args, stdin):
    flags, pos = split_args(args)
    err, rc = [], 0
    for a in pos:
        e = sh.fs.mkdir(sh.path(a), parents="p" in flags, owner=sh.user)
        if e:
            err.append(f"mkdir: cannot create directory '{a}': {e}\n"); rc = 1
    return "", "".join(err), rc


def cmd_rm(sh, args, stdin):
    flags, pos = split_args(args)
    rec, force = bool(flags & {"r", "R"}), "f" in flags
    err, rc = [], 0
    for a in pos:
        ap = sh.path(a)
        if ap == "/" and rec:
            return "", ("rm: it is dangerous to operate recursively on '/'\n"
                        "rm: use --no-preserve-root to override this failsafe\n"), 1
        if sh.fs.isdir(ap) and not rec:
            err.append(f"rm: cannot remove '{a}': Is a directory\n"); rc = 1; continue
        e = sh.fs.remove(ap, rec)
        if e and not (force and e == "No such file or directory"):
            err.append(f"rm: cannot remove '{a}': {e}\n"); rc = 1
    return "", "".join(err), rc


def _apply_mode(spec, cur):
    if re.fullmatch(r"[0-7]{3,4}", spec):
        return int(spec, 8)
    m = re.fullmatch(r"([ugoa]*)([+\-=])([rwx]+)", spec)
    if not m:
        return None
    who, op, perms = m.groups()
    targets = "ugo" if (not who or "a" in who) else who
    bits = sum({"r": 4, "w": 2, "x": 1}[p] for p in set(perms))
    shifts = {"u": 6, "g": 3, "o": 0}
    mask = sum(bits << shifts[t] for t in targets)
    if op == "+":
        return cur | mask
    if op == "-":
        return cur & ~mask
    return (cur & ~sum(7 << shifts[t] for t in targets)) | mask


def cmd_chmod(sh, args, stdin):
    _, pos = split_args([a for a in args if not re.fullmatch(r"-[rRfv]+", a)])
    if len(pos) < 2:
        return "", "chmod: missing operand after '" + (pos[0] if pos else "") + "'\n", 1
    spec, err, rc = pos[0], [], 0
    for a in pos[1:]:
        ap = sh.path(a)
        n = sh.fs.get(ap)
        if n is None:
            err.append(f"chmod: cannot access '{a}': No such file or directory\n"); rc = 1; continue
        mode = _apply_mode(spec, n.mode)
        if mode is None:
            return "", f"chmod: invalid mode: '{spec}'\n", 1
        sh.fs.chmod(ap, mode)
    return "", "".join(err), rc


# ---------------------------------------------------------------- text tools
def cmd_echo(sh, args, stdin):
    nl, esc = True, False
    while args and re.fullmatch(r"-[neE]+", args[0]):
        nl = nl and "n" not in args[0]
        esc = esc or "e" in args[0]
        args = args[1:]
    s = " ".join(args)
    if esc:
        s = s.replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")
    return s + ("\n" if nl else ""), "", 0


def _inputs(sh, files, stdin, cmd):
    """-> (list of (name, text), err, rc)"""
    if not files:
        return [("-", stdin)], "", 0
    res, err, rc = [], [], 0
    for a in files:
        n = sh.fs.get(sh.path(a))
        if n is None:
            err.append(f"{cmd}: {a}: No such file or directory\n"); rc = 2
        elif n.kind == "d":
            err.append(f"{cmd}: {a}: Is a directory\n"); rc = 2
        elif not can_read(sh, n):
            err.append(f"{cmd}: {a}: Permission denied\n"); rc = 2
        else:
            res.append((a, n.content))
    return res, "".join(err), rc


def cmd_grep(sh, args, stdin):
    flags, pos = split_args(args)
    if not pos:
        return "", "Usage: grep [OPTION]... PATTERNS [FILE]...\n", 2
    pat, files = pos[0], pos[1:]
    # ReDoS guard: attacker-controlled regex runs in our process
    if len(pat) > 100 or re.search(r"[+*}]\)?[+*{]", pat):
        pat = re.escape(pat)
    try:
        rx = re.compile(pat, re.I if "i" in flags else 0)
    except re.error:
        rx = re.compile(re.escape(pat), re.I if "i" in flags else 0)
    inputs, err, rc_in = _inputs(sh, files, stdin, "grep")
    out, found = [], False
    for name, text in inputs:
        cnt = 0
        for i, line in enumerate(text.splitlines(), 1):
            if bool(rx.search(line)) != ("v" in flags):
                cnt += 1; found = True
                if "c" not in flags:
                    pre = (f"{name}:" if len(files) > 1 else "") + (f"{i}:" if "n" in flags else "")
                    out.append(pre + line + "\n")
        if "c" in flags:
            out.append((f"{name}:" if len(files) > 1 else "") + f"{cnt}\n")
    return "".join(out), err, (2 if rc_in else (0 if found else 1))


def cmd_wc(sh, args, stdin):
    flags, pos = split_args(args)
    inputs, err, rc = _inputs(sh, pos, stdin, "wc")
    sel = [c for c in "lwc" if c in flags] or list("lwc")
    out = []
    for name, text in inputs:
        vals = {"l": text.count("\n"), "w": len(text.split()), "c": len(text.encode())}
        nums = [vals[c] for c in sel]
        width = 7 if (not pos and len(sel) > 1) else len(str(max(nums)))
        line = " ".join(f"{v:>{width}}" for v in nums)
        out.append(line + (f" {name}" if pos else "") + "\n")
    return "".join(out), err, rc


def _head_tail(tail):
    def fn(sh, args, stdin):
        n, rest, i = 10, [], 0
        while i < len(args):
            a = args[i]
            if a == "-n" and i + 1 < len(args) and args[i + 1].lstrip("+-").isdigit():
                n = int(args[i + 1]); i += 1
            elif re.fullmatch(r"-\d+", a):
                n = int(a[1:])
            elif not a.startswith("-") or a == "-":
                rest.append(a)
            i += 1
        inputs, err, rc = _inputs(sh, rest, stdin, "tail" if tail else "head")
        out = []
        for _, text in inputs:
            lines = text.splitlines(keepends=True)
            out.extend(lines[-n:] if (tail and n) else lines[:n])
        return "".join(out), err, rc
    return fn


# ---------------------------------------------------------------- system info
def cmd_whoami(sh, args, stdin): return sh.user + "\n", "", 0
def cmd_hostname(sh, args, stdin): return sh.hostname + "\n", "", 0
def cmd_nproc(sh, args, stdin): return f"{sh.profile.get('nproc', 1)}\n", "", 0
def cmd_clear(sh, args, stdin): return "\x1b[H\x1b[2J", "", 0
def cmd_true(sh, args, stdin): return "", "", 0
def cmd_false(sh, args, stdin): return "", "", 1


def cmd_id(sh, args, stdin):
    return f"uid={sh.uid}({sh.user}) gid={sh.gid}({sh.user}) groups={sh.gid}({sh.user})\n", "", 0


def cmd_uname(sh, args, stdin):
    u = sh.profile["uname"]
    flags, _ = split_args(args)
    if "a" in flags:
        s = f"{u['sysname']} {u['nodename']} {u['release']} {u['version']} {u['machine']} {u['machine']} {u['machine']} {u['os']}"
        return s + "\n", "", 0
    fields = [("s", "sysname"), ("n", "nodename"), ("r", "release"), ("v", "version"),
              ("m", "machine"), ("p", "machine"), ("i", "machine"), ("o", "os")]
    picked = [u[k] for f, k in fields if f in flags]
    return (" ".join(picked) if picked else u["sysname"]) + "\n", "", 0


def cmd_uptime(sh, args, stdin):
    d = sh.profile.get("uptime_days", 1)
    return f" {time.strftime('%H:%M:%S')} up {d} days,  3:41,  1 user,  load average: 0.08, 0.03, 0.01\n", "", 0


def cmd_free(sh, args, stdin):
    flags, _ = split_args(args)
    m = sh.profile["mem_kb"]
    def f(v):
        if "h" in flags:
            return f"{v / 1048576:.1f}Gi" if v >= 1048576 else f"{v // 1024}Mi"
        return str(v // 1024 if "m" in flags else v)
    row = lambda lab, *v: f"{lab:<7}" + "".join(f"{f(x) if isinstance(x, int) else x:>12}" for x in v) + "\n"
    head = f"{'':<7}" + "".join(f"{h:>12}" for h in ("total", "used", "free", "shared", "buff/cache", "available")) + "\n"
    return head + row("Mem:", m["total"], m["used"], m["free"], m["shared"], m["buff_cache"], m["available"]) + row("Swap:", 0, 0, 0), "", 0


def cmd_ps(sh, args, stdin):
    flags, pos = split_args(args)
    procs = sh.profile.get("processes", [])
    me, ps = 2311, 2342
    if not (flags & {"a", "e", "u", "x", "f"}) and not any(p in ("aux", "ef", "-ef") for p in pos):
        return (f"    PID TTY          TIME CMD\n{me:>7} pts/0    00:00:00 bash\n{ps:>7} pts/0    00:00:00 ps\n"), "", 0
    full_ef = "f" in flags or "ef" in pos
    if full_ef and "u" not in flags:
        out = "UID          PID    PPID  C STIME TTY          TIME CMD\n"
        for u, pid, _, _, _, _, tty, _, start, t, cmd in procs:
            out += f"{u:<8} {pid:>7} {0 if pid in (1, 2) else 1:>7}  0 {start} {tty:<8} 00:{t.zfill(5)} {cmd}\n"
        out += f"{sh.user:<8} {me:>7}     812  0 {time.strftime('%H:%M')} pts/0    00:00:00 -bash\n"
        out += f"{sh.user:<8} {ps:>7} {me:>7}  0 {time.strftime('%H:%M')} pts/0    00:00:00 ps -ef\n"
        return out, "", 0
    out = "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
    for u, pid, cpu, mem, vsz, rss, tty, stat, start, t, cmd in procs:
        out += f"{u:<8} {pid:>7} {cpu:>4} {mem:>4} {vsz:>6} {rss:>5} {tty:<8} {stat:<4} {start:<5} {t:>5} {cmd}\n"
    out += f"{sh.user:<8} {me:>7}  0.0  0.1   8272  5120 pts/0    Ss   {time.strftime('%H:%M')}   0:00 -bash\n"
    out += f"{sh.user:<8} {ps:>7}  0.0  0.1  10072  3328 pts/0    R+   {time.strftime('%H:%M')}   0:00 ps aux\n"
    return out, "", 0


def cmd_which(sh, args, stdin):
    _, pos = split_args(args)
    out, rc = [], 1 if not pos else 0
    for a in pos:
        if a in COMMANDS or a in ("exit", "export"):
            out.append(f"/usr/bin/{a}\n")
        else:
            rc = 1
    return "".join(out), "", rc


# ---------------------------------------------------------------- downloaders: log, never fetch
def _host(url):
    return urlsplit(url if "://" in url else "http://" + url).hostname or url


def cmd_wget(sh, args, stdin):
    valued = {"-O", "-P", "-o", "-t", "-T", "-U", "-e", "-i"}
    url, i, quiet = None, 0, False
    while i < len(args):
        a = args[i]
        if a in valued:
            i += 1
        elif a.startswith("-"):
            quiet = quiet or a in ("-q", "--quiet")
        elif url is None:
            url = a
        i += 1
    if url is None:
        return "", "wget: missing URL\nUsage: wget [OPTION]... [URL]...\n\nTry `wget --help' for more options.\n", 1
    sh.emit("download_attempt", tool="wget", url=url, args=" ".join(args))
    if quiet:
        return "", "", 4
    host = _host(url)
    err = (f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
           f"Resolving {host} ({host})... failed: Temporary failure in name resolution.\n"
           f"wget: unable to resolve host address \u2018{host}\u2019\n")
    return "", err, 4


def cmd_curl(sh, args, stdin):
    valued = {"-o", "-H", "-d", "-X", "-A", "-u", "-e", "-m", "-b", "-F", "-T"}
    url, i = None, 0
    silent = show = False
    while i < len(args):
        a = args[i]
        if a in valued:
            i += 1
        elif a.startswith("--"):
            silent = silent or a == "--silent"; show = show or a == "--show-error"
        elif a.startswith("-") and len(a) > 1:
            silent = silent or "s" in a; show = show or "S" in a
        elif url is None:
            url = a
        i += 1
    if url is None:
        return "", "curl: try 'curl --help' or 'curl --manual' for more information\n", 2
    sh.emit("download_attempt", tool="curl", url=url, args=" ".join(args))
    if silent and not show:
        return "", "", 6
    return "", f"curl: (6) Could not resolve host: {_host(url)}\n", 6


COMMANDS = {
    "pwd": cmd_pwd, "cd": cmd_cd, "ls": cmd_ls, "cat": cmd_cat, "touch": cmd_touch,
    "mkdir": cmd_mkdir, "rm": cmd_rm, "chmod": cmd_chmod, "echo": cmd_echo,
    "grep": cmd_grep, "egrep": cmd_grep, "wc": cmd_wc,
    "head": _head_tail(False), "tail": _head_tail(True),
    "whoami": cmd_whoami, "hostname": cmd_hostname, "nproc": cmd_nproc, "clear": cmd_clear,
    "true": cmd_true, "false": cmd_false, "id": cmd_id, "uname": cmd_uname,
    "uptime": cmd_uptime, "free": cmd_free, "ps": cmd_ps, "which": cmd_which,
    "wget": cmd_wget, "curl": cmd_curl,
}
