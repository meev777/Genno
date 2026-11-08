from genno.shell.profile import load_profile
from genno.shell.vfs import SessionFS, normalize, MAX_FILE

def fs(): return SessionFS(load_profile("ubuntu-web").base)

def test_normalize_clamps_traversal():
    assert normalize("/root", "../../../../etc/passwd") == "/etc/passwd"
    assert normalize("/", "..") == "/"
    assert normalize("/root", "~/a/./b") == "/root/a/b"
    assert normalize("/a", "//x///y/") == "/x/y"

def test_copy_on_write_isolated_between_sessions():
    a, b = fs(), fs()
    assert a.write("/tmp/x", "hi") is None
    assert a.get("/tmp/x").content == "hi"
    assert b.get("/tmp/x") is None
    assert "x" not in a.base.children["/tmp"]
    a.write("/etc/passwd", "owned")
    assert b.get("/etc/passwd").content.startswith("root:x:0:0")

def test_remove_recursive_hides_descendants_and_recreate():
    a = fs()
    assert a.remove("/var/www") == "Directory not empty"
    assert a.remove("/var/www", recursive=True) is None
    assert not a.exists("/var/www/html/index.html") and not a.exists("/var/www")
    assert fs().exists("/var/www/html/index.html")
    assert a.mkdir("/var/www") is None and a.listdir("/var/www") == []

def test_limits():
    a = fs()
    assert a.write("/tmp/big", "x" * (MAX_FILE + 1)) == "File too large"
    assert a.write("/nope/x", "1") == "No such file or directory"
    assert a.write("/etc", "1") == "Is a directory"
    for i in range(600):
        if a.write(f"/tmp/f{i}", "") :
            break
    assert len(a.overlay) <= 500
