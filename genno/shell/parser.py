"""Bash-subset parser: quotes, escapes, $VAR, ~, ; && || | & and redirects (> >> < 2> 2>&1 &>).

Words keep per-segment quoting info so expansion happens at execution time
(`false; echo $?` works) and single quotes suppress expansion.
Not supported (by design): $(...), backticks, globbing, heredocs, subshells.
"""
import re
from dataclasses import dataclass, field

_VAR = re.compile(r"\$(?:\{([A-Za-z_]\w*)\}|([A-Za-z_]\w*)|(\?))")


class ParseError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class Word:
    __slots__ = ("segs",)
    def __init__(self, segs): self.segs = segs
    def raw(self): return "".join(t for t, _ in self.segs)
    @property
    def unquoted(self): return all(k == "u" for _, k in self.segs)
    def __repr__(self): return f"Word({self.raw()!r})"

    def expand(self, env, home):
        out = []
        for i, (t, k) in enumerate(self.segs):
            if k in ("u", "d"):
                if i == 0 and k == "u" and (t == "~" or t.startswith("~/")):
                    t = home + t[1:]
                t = _VAR.sub(lambda m: env.get(m.group(1) or m.group(2) or m.group(3), ""), t)
            out.append(t)
        return "".join(out)


@dataclass
class Redir:
    fd: object      # 1, 2 or None
    op: str         # > >> < >& &>
    target: Word


@dataclass
class Cmd:
    words: list = field(default_factory=list)
    redirs: list = field(default_factory=list)


def tokenize(s):
    toks, cur, i, n = [], [], 0, len(s)

    def seg(text, kind):
        if cur and cur[-1][1] == kind:
            cur[-1] = (cur[-1][0] + text, kind)
        else:
            cur.append((text, kind))

    def flush():
        if cur:
            toks.append(("w", Word(list(cur)), None))
            cur.clear()

    while i < n:
        c = s[i]
        if c in " \t\n":
            flush(); i += 1
        elif c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise ParseError("bash: unexpected EOF while looking for matching `''")
            seg(s[i + 1:j], "s"); i = j + 1
        elif c == '"':
            j, part = i + 1, []
            while j < n and s[j] != '"':
                if s[j] == "\\" and j + 1 < n and s[j + 1] in '"\\$`':
                    if part:
                        seg("".join(part), "d"); part = []
                    seg(s[j + 1], "s"); j += 2
                else:
                    part.append(s[j]); j += 1
            if j >= n:
                raise ParseError("bash: unexpected EOF while looking for matching `\"'")
            seg("".join(part), "d")   # may be "" -> keeps empty-string args
            i = j + 1
        elif c == "\\":
            if i + 1 < n:
                seg(s[i + 1], "s")
            i += 2
        elif c == "#" and not cur:
            break
        elif c in ";|&<>":
            fd = None
            if c == ">" and len(cur) == 1 and cur[0][1] == "u" and cur[0][0] in ("1", "2"):
                fd = int(cur[0][0]); cur.clear()
            else:
                flush()
            two = s[i:i + 2]
            if two in ("&&", "||", ">>", ">&", "&>"):
                op, i = two, i + 2
            else:
                op, i = c, i + 1
            toks.append(("op", op, fd))
        else:
            seg(c, "u"); i += 1
    flush()
    return toks


def parse(line):
    """-> list of (preceding_op, [Cmd, ...]) ; preceding_op in {';','&&','||'}"""
    toks = tokenize(line)
    items, pipeline, cmd, pending, dangling = [], [], Cmd(), ";", False
    empty = lambda c: not c.words and not c.redirs
    i = 0
    while i < len(toks):
        kind, val, fd = toks[i]
        if kind == "w" or val in (">", ">>", "<", ">&", "&>"):
            dangling = False
        if kind == "w":
            cmd.words.append(val)
        elif val in (">", ">>", "<", ">&", "&>"):
            if i + 1 >= len(toks):
                raise ParseError("bash: syntax error near unexpected token `newline'")
            nk, nv, _ = toks[i + 1]
            if nk != "w":
                raise ParseError(f"bash: syntax error near unexpected token `{nv}'")
            cmd.redirs.append(Redir(fd, val, nv)); i += 1
        elif val == "|":
            if empty(cmd):
                raise ParseError("bash: syntax error near unexpected token `|'")
            pipeline.append(cmd); cmd = Cmd()
        else:  # ; && || &
            if empty(cmd):
                raise ParseError(f"bash: syntax error near unexpected token `{val}'")
            pipeline.append(cmd)
            items.append((pending, pipeline))
            pipeline, cmd = [], Cmd()
            pending = ";" if val == "&" else val
            dangling = val in ("&&", "||")
        i += 1
    if not empty(cmd):
        pipeline.append(cmd)
        items.append((pending, pipeline))
    elif pipeline or dangling:   # dangling "|" / "&&" / "||"
        raise ParseError("bash: syntax error: unexpected end of file")
    return items
