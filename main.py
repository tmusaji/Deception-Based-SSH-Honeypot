"""
Deception-Based SSH Honeypot (Paramiko)
========================================
Speaks real SSH protocol so standard SSH clients connect cleanly.

Install:
    pip install paramiko colorama

Run:
    python ssh_honeypot.py                  # default port 2222
    python ssh_honeypot.py --port 2222
    sudo python ssh_honeypot.py --port 22   # port 22 needs root

Test (from any other terminal):
    ssh root@<your-ip> -p 2222
    ssh admin@<your-ip> -p 2222

Fake credentials that grant fake-shell access:
    root  / 12345678
    admin / admin123

Any other username/password → "Permission denied, please try again."
5+ failed attempts from the same IP → BRUTE FORCE alert.
"""

import os
import socket
import threading
import logging
import argparse
from datetime import datetime

import paramiko

# ─── Optional color support ───────────────────────────────────────────────────
try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
    RED    = Fore.RED
    YELLOW = Fore.YELLOW
    GREEN  = Fore.GREEN
    CYAN   = Fore.CYAN
    RESET  = Style.RESET_ALL
except ImportError:
    RED = YELLOW = GREEN = CYAN = RESET = ""


# ─── Config ───────────────────────────────────────────────────────────────────
DEFAULT_HOST          = "0.0.0.0"
DEFAULT_PORT          = 2222
DEFAULT_LOGFILE       = "honeypot.log"
BRUTE_FORCE_THRESHOLD = 5          # failed attempts before brute-force alert
HOST_KEY_FILE         = "honeypot_rsa.key"   # auto-generated on first run

# Credentials that "work" — attacker lands in monitored fake shell
FAKE_CREDENTIALS = {
    "root":  "12345678",
    "admin": "admin123",
}

# ── Risk patterns ─────────────────────────────────────────────────────────────
HIGH_RISK = [
    "cat /etc/passwd", "cat /etc/shadow", "rm -rf",
    "wget ", "curl ", "chmod ", "sudo ", "nc ",
    "python -c", "perl -e", "bash -i", "mkfifo",
    "base64 -d", "/bin/sh", "dd if=",
]
MEDIUM_RISK = [
    "ls -la", "ps aux", "netstat", "ifconfig",
    "who", "last", "history", "find /",
    "env", "uname", "id", "hostname",
]

# ── Fake command outputs ──────────────────────────────────────────────────────
FAKE_CMD_OUTPUT = {
    "ls":              "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
    "ls -la":          "total 64\ndrwxr-xr-x 19 root root 4096 Jan  6 03:42 .\ndrwxr-xr-x 19 root root 4096 Jan  6 03:42 ..\ndrwxr-xr-x  2 root root 4096 Jan  6 03:40 bin\ndrwxr-xr-x  3 root root 4096 Jan  6 03:40 etc",
    "pwd":             "/root",
    "whoami":          "root",
    "id":              "uid=0(root) gid=0(root) groups=0(root)",
    "uname":           "Linux",
    "uname -a":        "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
    "hostname":        "honeypot",
    "ps aux":          "  PID USER    COMMAND\n    1 root    /sbin/init\n   42 root    sshd\n  101 root    bash",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
    "cat /etc/shadow": "root:$6$xyz$hashedpassword:19000:0:99999:7:::\ndaemon:*:18375:0:99999:7:::",
    "ifconfig":        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 192.168.1.100  netmask 255.255.255.0",
    "netstat -an":     "Active Internet connections\nProto  Local Address       Foreign Address     State\ntcp    0.0.0.0:22          0.0.0.0:*           LISTEN",
    "env":             "HOME=/root\nPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\nSHELL=/bin/bash",
    "history":         "    1  ls\n    2  cat /etc/passwd\n    3  wget http://example.com/shell.sh\n    4  chmod +x shell.sh",
    "find /":          "/\n/bin\n/etc\n/etc/passwd\n/etc/shadow\n/home\n/root\n/var\n/var/log",
    "who":             "root     pts/0        2025-01-06 03:42 (192.168.1.77)",
    "last":            "root     pts/0        192.168.1.77     Mon Jan  6 03:42   still logged in",
    "w":               " 03:42:01 up 12 days,  4:20,  1 user\nUSER     TTY      FROM          LOGIN@   WHAT\nroot     pts/0    192.168.1.77  03:42    -bash",
}


# ─── Logger ───────────────────────────────────────────────────────────────────
def _make_logger(logfile: str) -> logging.Logger:
    log = logging.getLogger("honeypot")
    log.setLevel(logging.DEBUG)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    fh = logging.FileHandler(logfile)
    fh.setFormatter(fmt)
    log.addHandler(fh)
    log.propagate = False
    return log


# ─── Detection engine ─────────────────────────────────────────────────────────
class DetectionEngine:
    def __init__(self, log: logging.Logger):
        self._log   = log
        self._lock  = threading.Lock()
        self._fails: dict[str, int] = {}
        self._brute: set[str]       = set()
        self.stats = dict(connections=0, logins=0, brute=0, highrisk=0, ips=set())

    # ── public events ─────────────────────────────────────────────────────────

    def on_connect(self, ip: str, port: int):
        with self._lock:
            self.stats["connections"] += 1
            self.stats["ips"].add(ip)
        self._show("LOW", ip, f"New SSH connection from {ip}:{port}")

    def on_fail(self, ip: str, user: str, pwd: str):
        with self._lock:
            self._fails[ip] = self._fails.get(ip, 0) + 1
            n = self._fails[ip]
        self._show("LOW", ip, f"Failed login #{n}  user='{user}'  pass='{pwd}'")
        if n >= BRUTE_FORCE_THRESHOLD and ip not in self._brute:
            self._brute.add(ip)
            with self._lock:
                self.stats["brute"] += 1
            self._show("HIGH", ip, f"⚠  BRUTE FORCE — {n} failed attempts from {ip}")

    def on_login(self, ip: str, user: str):
        with self._lock:
            self.stats["logins"] += 1
        self._show("MEDIUM", ip, f"Fake credentials accepted  user='{user}'  — shell session started")

    def on_cmd(self, ip: str, user: str, cmd: str):
        risk = self._risk(cmd)
        if risk == "HIGH":
            with self._lock:
                self.stats["highrisk"] += 1
        self._show(risk, ip, f"CMD [{risk}]  user='{user}'  $ {cmd}")

    def on_disconnect(self, ip: str, secs: float, n_cmds: int):
        msg = f"Session closed  duration={secs:.1f}s  cmds={n_cmds}"
        self._log.info(f"[{ip}] {msg}")
        print(f"{CYAN}[{_ts()}][END   ] [{ip}] {msg}{RESET}")

    # ── helpers ───────────────────────────────────────────────────────────────

    def _risk(self, cmd: str) -> str:
        c = cmd.lower()
        if any(p in c for p in HIGH_RISK):   return "HIGH"
        if any(p in c for p in MEDIUM_RISK): return "MEDIUM"
        return "LOW"

    def _show(self, level: str, ip: str, msg: str):
        color = {  "HIGH": RED, "MEDIUM": YELLOW, "LOW": CYAN }.get(level, "")
        print(f"{color}[{_ts()}][{level:6s}] [{ip}] {msg}{RESET}")
        fn = self._log.warning if level == "HIGH" else self._log.info
        fn(f"[{level}] [{ip}] {msg}")

    def summary(self):
        s = self.stats
        print(f"\n{CYAN}{'─'*55}")
        print("  HONEYPOT SUMMARY")
        print(f"{'─'*55}{RESET}")
        print(f"  Connections      : {s['connections']}")
        print(f"  Unique IPs       : {len(s['ips'])}")
        print(f"  Successful logins: {s['logins']}")
        print(f"  Brute-force      : {s['brute']}")
        print(f"  High-risk cmds   : {s['highrisk']}")
        if s["ips"]:
            print(f"  IPs seen         : {', '.join(s['ips'])}")
        print(f"{CYAN}{'─'*55}{RESET}\n")


def _ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


# ─── Paramiko server interface ────────────────────────────────────────────────
class HoneypotServerInterface(paramiko.ServerInterface):
    """
    Paramiko calls these methods during the SSH handshake.
    We use them to capture credentials and decide access.
    """

    def __init__(self, ip: str, engine: DetectionEngine):
        self.ip        = ip
        self.engine    = engine
        self.username  = ""
        # Event set when the client requests a shell/exec
        self.shell_event = threading.Event()

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        expected = FAKE_CREDENTIALS.get(username)
        if expected and password == expected:
            self.engine.on_login(self.ip, username)
            return paramiko.AUTH_SUCCESSFUL
        else:
            self.engine.on_fail(self.ip, username, password)
            return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        # Reject all key-based auth — force password prompt
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel) -> bool:
        self.shell_event.set()
        return True

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        self.shell_event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return True


# ─── Fake shell ───────────────────────────────────────────────────────────────
class FakeShell:
    PROMPT = "root@honeypot:~# "

    def __init__(self, channel: paramiko.Channel, ip: str, username: str, engine: DetectionEngine):
        self.chan    = channel
        self.ip     = ip
        self.user   = username
        self.engine = engine
        self.n_cmds = 0
        self.start  = datetime.now()

    def run(self):
        self._write(
            f"\r\nWelcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n"
            f" * Documentation:  https://help.ubuntu.com\r\n"
            f"Last login: Mon Jan  6 03:42:11 2025 from 10.0.0.77\r\n\r\n"
        )
        self._write(self.PROMPT)

        buf = ""
        while True:
            try:
                data = self.chan.recv(1024)
            except Exception:
                break
            if not data:
                break

            for byte in data:
                ch = chr(byte)

                # Enter — process command
                if ch in ("\r", "\n"):
                    self._write("\r\n")
                    cmd = buf.strip()
                    buf = ""
                    if cmd:
                        self.n_cmds += 1
                        self.engine.on_cmd(self.ip, self.user, cmd)
                        out = self._respond(cmd)
                        if out is None:          # exit
                            self._write("logout\r\n")
                            self.chan.close()
                            return
                        if out:
                            self._write(out + "\r\n")
                    self._write(self.PROMPT)

                # Backspace
                elif ch in ("\x7f", "\x08"):
                    if buf:
                        buf = buf[:-1]
                        self._write("\x08 \x08")   # erase character on terminal

                # Ctrl-C
                elif ch == "\x03":
                    buf = ""
                    self._write("^C\r\n" + self.PROMPT)

                # Ctrl-D (EOF)
                elif ch == "\x04":
                    self._write("\r\nlogout\r\n")
                    self.chan.close()
                    return

                # Printable character — echo and buffer
                elif ch.isprintable():
                    buf += ch
                    self._write(ch)

        duration = (datetime.now() - self.start).total_seconds()
        self.engine.on_disconnect(self.ip, duration, self.n_cmds)

    def _write(self, text: str):
        try:
            self.chan.sendall(text.encode())
        except Exception:
            pass

    def _respond(self, cmd: str) -> str | None:
        if cmd in ("exit", "quit", "logout"):
            return None

        if cmd in FAKE_CMD_OUTPUT:
            return FAKE_CMD_OUTPUT[cmd]

        # Prefix match
        for key, val in FAKE_CMD_OUTPUT.items():
            if cmd.startswith(key + " "):
                return val

        # wget / curl — simulate failed download
        if cmd.startswith(("wget ", "curl ")):
            target = cmd.split(" ", 1)[1]
            return (f"--2025-01-06 03:42:11--  {target}\n"
                    f"Resolving host... failed: Name or service not known.")

        # Silent commands
        if any(cmd.startswith(p) for p in ("chmod ", "sudo ", "rm ", "mv ", "cp ", "mkdir ", "touch ")):
            return ""

        base = cmd.split()[0]
        return f"-bash: {base}: command not found"


# ─── Per-connection thread ────────────────────────────────────────────────────
def _handle(conn: socket.socket, addr, host_key: paramiko.RSAKey, engine: DetectionEngine):
    ip = addr[0]
    transport = None
    try:
        transport = paramiko.Transport(conn)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"
        transport.add_server_key(host_key)

        server_iface = HoneypotServerInterface(ip, engine)

        try:
            transport.start_server(server=server_iface)
        except paramiko.SSHException:
            return

        # Wait for a channel (up to 30 s)
        channel = transport.accept(30)
        if channel is None:
            return

        # Wait for shell request (up to 10 s)
        server_iface.shell_event.wait(10)

        shell = FakeShell(channel, ip, server_iface.username, engine)
        shell.run()

    except Exception as e:
        engine._log.debug(f"[{ip}] Transport error: {e}")
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass


# ─── Host key ─────────────────────────────────────────────────────────────────
def _load_or_create_key(path: str) -> paramiko.RSAKey:
    if os.path.exists(path):
        return paramiko.RSAKey(filename=path)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(path)
    print(f"{GREEN}[INFO] Generated new RSA host key → {path}{RESET}")
    return key


# ─── Main server ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="SSH Honeypot (paramiko)")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--log",  default=DEFAULT_LOGFILE)
    args = parser.parse_args()

    log      = _make_logger(args.log)
    engine   = DetectionEngine(log)
    host_key = _load_or_create_key(HOST_KEY_FILE)

    # Suppress paramiko's own noisy logging
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((args.host, args.port))
    except PermissionError:
        print(f"{RED}[ERROR] Permission denied — use --port 2222 or run as root for port 22.{RESET}")
        raise SystemExit(1)
    srv.listen(10)

    print(f"{GREEN}{'─'*55}")
    print("  SSH Honeypot  (real SSH protocol via paramiko)")
    print(f"{'─'*55}{RESET}")
    print(f"  Listening          : {args.host}:{args.port}")
    print(f"  Log file           : {args.log}")
    print(f"  Brute-force after  : {BRUTE_FORCE_THRESHOLD} failed attempts")
    print(f"  Fake credentials   : root/12345678   admin/admin123")
    print(f"  Any other creds    : 'Permission denied, please try again.'")
    print(f"{GREEN}{'─'*55}{RESET}\n")

    try:
        while True:
            conn, addr = srv.accept()
            engine.on_connect(addr[0], addr[1])
            t = threading.Thread(
                target=_handle,
                args=(conn, addr, host_key, engine),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[INFO] Stopping...{RESET}")
    finally:
        srv.close()
        engine.summary()


if __name__ == "__main__":
    main()
