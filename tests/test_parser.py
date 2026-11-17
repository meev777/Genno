import pytest
from genno.shell.parser import parse, ParseError

def flat(line):
    return [(op, [[w.raw() for w in c.words] for c in p]) for op, p in parse(line)]

def test_operators_and_pipes():
    assert flat("a; b && c || d | e") == [
        (";", [["a"]]), (";", [["b"]]), ("&&", [["c"]]), ("||", [["d"], ["e"]])]
    assert flat("a &") == [(";", [["a"]])]
    assert flat("") == [] and flat("  # comment") == []

def test_quotes_keep_operators_literal():
    assert flat('echo ";" "|" \'a b\' "c\\"d"') == [(";", [["echo", ";", "|", "a b", 'c"d']])]
    assert flat('echo ""') == [(";", [["echo", ""]])]

def test_redirects():
    c = parse("cat < in > out 2>/dev/null 2>&1 >> log")[0][1][0]
    assert [(r.fd, r.op, r.target.raw()) for r in c.redirs] == [
        (None, "<", "in"), (None, ">", "out"), (2, ">", "/dev/null"), (2, ">&", "1"), (None, ">>", "log")]
    c = parse("echo 2 > f")[0][1][0]
    assert [w.raw() for w in c.words] == ["echo", "2"]

@pytest.mark.parametrize("bad", ["; id", "id ;; id", "a | | b", "a >", "a &&", "echo 'x", 'echo "x'])
def test_syntax_errors(bad):
    with pytest.raises(ParseError):
        parse(bad)
