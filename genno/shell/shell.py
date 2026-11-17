"""Per-session shell: parse -> expand -> dispatch to emulated commands. Never spawns a process."""
import re
from .commands import COMMANDS
from .parser import parse, ParseError
from .profile import load_profile
from .vfs import SessionFS, normalize

MAX_LINE = 4096
MAX_OUT = 64 * 1024
_ASSIGN = re.compile(r"^([A-Za-z_]\w*)=(.*)$", re.S)


class Shell:
    def __init__(self, profile="ubuntu-web", user="root", emit=None, tty=False, fs=None):
        self.profile = load_profile(profile) if isinstance(profile, str) else profile
        self.user, self.tty = user, tty
        self.hostname = self.profile["hostname"]
        pu = self.profile["users"].get(user) or {
            "uid": 1001, "gid": 1001, "home": "/root" if user == "root" else f"/home/{user}"}
        self.uid, self.gid, self.home = pu["uid"], pu["gid"], pu["home"]
        self.fs = fs if fs is not None else SessionFS(self.profile.base)
        if not self.fs.isdir(self.home):
            self.fs.mkdir(self.home, parents=True, owner=user)
        self.cwd = self.oldpwd = self.home
        self.vars, self.last_rc, self.exited, self._depth = {}, 0, False, 0
        self.emit = emit or (lambda event_type, **fields: None)

    def path(self, p):
        return normalize(self.cwd, p, self.home)

    def env(self):
        return {"HOME": self.home, "USER": self.user, "LOGNAME": self.user, "PWD": self.cwd,
                "SHELL": "/bin/bash", "HOSTNAME": self.hostname, "TERM": "xterm",
                "LANG": "en_US.UTF-8", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                **self.vars, "?": str(self.last_rc)}

    def prompt(self):
        if self.cwd == self.home:
            where = "~"
        elif self.cwd.startswith(self.home.rstrip("/") + "/"):
            where = "~" + self.cwd[len(self.home.rstrip("/")):]
        else:
            where = self.cwd
        return f"{self.user}@{self.hostname}:{where}{'#' if self.uid == 0 else '$'} "

    def run(self, line):
        if len(line) > MAX_LINE:
            self.last_rc = 1
            return "bash: argument list too long\n"
        try:
            items = parse(line)
        except ParseError as e:
            self.last_rc = 2
            return e.message + "\n"
        out, rc = [], self.last_rc
        for op, cmds in items:
            if (op == "&&" and rc != 0) or (op == "||" and rc == 0):
                continue
            text, rc = self._pipeline(cmds)
            out.append(text)
            self.last_rc = rc
            if self.exited:
                break
        return "".join(out)[:MAX_OUT]

    def _pipeline(self, cmds):
        errs, stdin, rc = [], "", 0
        for cmd in cmds:
            out, err, rc = self._cmd(cmd, stdin)
            errs.append(err)
            stdin = out[:MAX_OUT]
        return "".join(errs) + stdin, rc

    def _cmd(self, cmd, stdin):
        env, argv = self.env(), []
        for w in cmd.words:
            s = w.expand(env, self.home)
            if s == "" and w.unquoted:
                continue
            argv.append(s)
        # input redirect
        for r in cmd.redirs:
            if r.op == "<":
                name = r.target.expand(env, self.home)
                n = self.fs.get(self.path(name))
                if n is None or n.kind != "f":
                    return "", f"bash: {name}: No such file or directory\n", 1
                stdin = n.content
        out, err, rc = self._dispatch(argv, stdin)
        # output redirects
        if any(r.op == "&>" or (r.op == ">&" and r.fd == 2 and r.target.raw() == "1") for r in cmd.redirs):
            out, err = out + err, ""
        for r in cmd.redirs:
            if r.op == "<" or (r.op == ">&" and r.target.raw() in ("1", "2")):
                continue
            to_err = r.fd == 2
            data = err if to_err else out
            name = r.target.expand(env, self.home)
            p = self.path(name)
            if p != "/dev/null":
                e = self.fs.write(p, data, append=r.op == ">>", owner=self.user)
                if e:
                    err += f"bash: {name}: {e}\n"; rc = 1
            if to_err:
                err = ""
            else:
                out = ""
        return out, err, rc

    def _dispatch(self, argv, stdin):
        if not argv:
            return "", "", 0
        name = argv[0]
        if name == "exit" or name == "logout":
            self.exited = True
            return "", "", int(argv[1]) & 0xFF if len(argv) > 1 and argv[1].isdigit() else self.last_rc
        if name == "export":
            for a in argv[1:]:
                m = _ASSIGN.match(a)
                if m:
                    self.vars[m.group(1)] = m.group(2)
            return "", "", 0
        m = _ASSIGN.match(name)
        if m and len(argv) == 1:
            self.vars[m.group(1)] = m.group(2)
            return "", "", 0
        if name.split("/")[-1] in ("sh", "bash", "dash") and (
                "/" not in name or name.startswith(("/bin/", "/usr/bin/"))):
            return self._shell_cmd(name.split("/")[-1], argv[1:], stdin)
        if "/" in name:
            return self._exec_path(name)
        fn = COMMANDS.get(name)
        if fn is None:
            return "", f"bash: {name}: command not found\n", 127
        try:
            return fn(self, argv[1:], stdin)
        except Exception:   # emulator bugs must never crash the session or leak a traceback
            return "", "", 1

    # --- scripts: run file/-c/stdin lines through the emulator (depth-limited)
    def _run_script(self, text):
        if self._depth >= 3:
            return "", "", 0
        self._depth += 1
        out = []
        try:
            for line in text.splitlines()[:200]:
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                out.append(self.run(line))
                if self.exited:          # `exit` ends the script, not the session
                    self.exited = False
                    break
            return "".join(out), "", self.last_rc
        finally:
            self._depth -= 1

    def _shell_cmd(self, name, args, stdin):
        if args and args[0] == "-c":
            if len(args) < 2:
                return "", f"{name}: -c: option requires an argument\n", 2
            return self._run_script(args[1])
        files = [a for a in args if not a.startswith("-")]
        if files:
            n = self.fs.get(self.path(files[0]))
            if n is None:
                return "", f"{name}: {files[0]}: No such file or directory\n", 127
            if n.kind != "f":
                return "", f"{name}: {files[0]}: Is a directory\n", 126
            return self._run_script(n.content)
        return self._run_script(stdin)

    def _exec_path(self, name):
        p = self.path(name)
        n = self.fs.get(p)
        if n is None:
            return "", f"bash: {name}: No such file or directory\n", 127
        if n.kind == "d":
            return "", f"bash: {name}: Is a directory\n", 126
        if not n.mode & 0o111:
            return "", f"bash: {name}: Permission denied\n", 126
        self.emit("exec_attempt", path=p)
        return self._run_script(n.content)
