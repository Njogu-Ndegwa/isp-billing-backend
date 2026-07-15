"""Secondary-server pull service (dependency-free, Python stdlib).

Per-router queue of provisioning commands, keyed so concurrent paying users never
overwrite each other. Serves each router's outbound check-in.

- GET  /<identity>.rsc              -> concatenation of that router's LIVE commands
                                       (or "# idle"); records a heartbeat
- POST /pull/set/<identity>/<key>   -> store/replace one command for this router  [auth]
- POST /pull/clear/<identity>/<key> -> remove one command (app confirmed it applied)[auth]
- POST /pull/clear/<identity>       -> remove all of a router's pending commands   [auth]
- GET  /pull/heartbeats             -> last check-in per router                    [auth]

WRITES require X-Pull-Token == $PULL_TOKEN (or come from an allowed IP) so nobody can
inject a command a router would execute.

EXPIRY (the fix for the free-internet bug): a command may carry a leading
``# PULL-EXPIRES <unixts>`` comment (RouterOS ignores it on import). Once that time
passes the command is DROPPED and never served again, so a delivered command can't keep
re-granting access after the customer's plan ends. A background pruner also sweeps every
router — including ones whose agent never checks in — so stale commands can't pile up.
Commands with no expiry header fall back to the mtime TTL as before.
"""
import os, re, json, time, threading, http.server, socketserver, urllib.parse

TOKEN = os.environ.get("PULL_TOKEN", "")
# Writes are also authorized from the billing server's IP, so the app can hand off
# commands without a token env (no app restart). Token still works as an alternative.
ALLOWED_POST_IPS = set(x.strip() for x in os.environ.get(
    "PULL_ALLOWED_IPS", "54.91.202.229").split(",") if x.strip())
DATA = os.environ.get("PULL_DATA", "/data")
PORT = int(os.environ.get("PULL_PORT", "8000"))
# Backstop for commands with NO expiry header. Commands WITH an expiry are governed by
# that expiry instead (the real paid window), which may be longer or shorter than this.
PULL_TTL = int(os.environ.get("PULL_TTL", "3600"))
# How often the background pruner sweeps every router's queue for dead commands.
PRUNE_INTERVAL = int(os.environ.get("PULL_PRUNE_INTERVAL", "60"))
HEARTBEATS = {}

_EXPIRES_RE = re.compile(rb"^#\s*PULL-EXPIRES\s+(\d+)\b")


def _parse_expires(path):
    """Return the unix-seconds expiry from a command file's leading
    ``# PULL-EXPIRES <ts>`` header, or None if it has none."""
    try:
        with open(path, "rb") as fh:
            first = fh.readline(256)
        m = _EXPIRES_RE.match(first)
        return int(m.group(1)) if m else None
    except Exception:
        return None


def _file_live(path, now):
    """True if the command should still be served. If it is dead (past its expiry, or
    — for legacy no-expiry commands — older than PULL_TTL) it is removed and False
    returned. Transient read errors keep the file (fail-open, never lose live work)."""
    try:
        exp = _parse_expires(path)
        if exp is not None:
            if now > exp:
                os.remove(path)
                return False
            return True
        if now - os.path.getmtime(path) > PULL_TTL:
            os.remove(path)
            return False
        return True
    except FileNotFoundError:
        return False
    except Exception:
        return True


def _router_dir(ident):
    d = os.path.join(DATA, ident)
    os.makedirs(d, exist_ok=True)
    return d


def _pending_rsc(ident, now=None):
    now = time.time() if now is None else now
    d = os.path.join(DATA, ident)
    if not os.path.isdir(d):
        return b"# idle\n"
    parts = []
    for name in sorted(os.listdir(d)):
        if not name.endswith(".rsc"):
            continue
        p = os.path.join(d, name)
        if not _file_live(p, now):
            continue
        try:
            with open(p, "rb") as fh:
                parts.append(fh.read())
        except Exception:
            pass
    return (b"\n".join(parts) + b"\n") if parts else b"# idle\n"


def _prune_all(now=None):
    """Sweep EVERY router's queue and drop dead commands. Runs even for routers whose
    agent never checks in (no GET), so undelivered commands can't accumulate forever."""
    now = time.time() if now is None else now
    removed = 0
    try:
        for ident in os.listdir(DATA):
            d = os.path.join(DATA, ident)
            if not os.path.isdir(d):
                continue
            for name in os.listdir(d):
                if name.endswith(".rsc"):
                    if not _file_live(os.path.join(d, name), now):
                        removed += 1
    except Exception:
        pass
    return removed


def _pruner_loop():
    while True:
        time.sleep(PRUNE_INTERVAL)
        _prune_all()


class H(http.server.BaseHTTPRequestHandler):
    def _auth(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        tok = self.headers.get("X-Pull-Token") or q.get("t", [""])[0]
        if bool(TOKEN) and tok == TOKEN:
            return True
        return self.client_address[0] in ALLOWED_POST_IPS

    def _send(self, code, body=b"", ctype="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/pull/heartbeats":
            if not self._auth():
                return self._send(403, "forbidden")
            return self._send(200, json.dumps(HEARTBEATS), "application/json")
        m = re.match(r"^/([A-Za-z0-9._-]{1,64})\.rsc$", path)
        if m:
            ident = m.group(1)
            HEARTBEATS[ident] = int(time.time())
            return self._send(200, _pending_rsc(ident))
        return self._send(404, "not found")

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if not self._auth():
            return self._send(403, "forbidden")
        m = re.match(r"^/pull/set/([A-Za-z0-9._-]{1,64})/([A-Za-z0-9._-]{1,64})$", path)
        if m:
            ident, key = m.group(1), m.group(2)
            n = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(n) if n > 0 else b""
            d = _router_dir(ident)
            with open(os.path.join(d, key + ".rsc"), "wb") as fh:
                fh.write(body)
            # prune this router's other stale commands on write
            now = time.time()
            for name in os.listdir(d):
                if name.endswith(".rsc"):
                    _file_live(os.path.join(d, name), now)
            return self._send(200, "set\n")
        m = re.match(r"^/pull/clear/([A-Za-z0-9._-]{1,64})/([A-Za-z0-9._-]{1,64})$", path)
        if m:
            ident, key = m.group(1), m.group(2)
            f = os.path.join(DATA, ident, key + ".rsc")
            if os.path.exists(f):
                os.remove(f)
            return self._send(200, "cleared\n")
        m = re.match(r"^/pull/clear/([A-Za-z0-9._-]{1,64})$", path)
        if m:
            d = os.path.join(DATA, m.group(1))
            if os.path.isdir(d):
                for name in os.listdir(d):
                    if name.endswith(".rsc"):
                        os.remove(os.path.join(d, name))
            return self._send(200, "cleared-all\n")
        return self._send(404, "not found")

    def log_message(self, *a):
        try:
            print(self.address_string(), self.command, self.path,
                  time.strftime("%H:%M:%S"), flush=True)
        except Exception:
            pass


class Srv(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    os.makedirs(DATA, exist_ok=True)
    threading.Thread(target=_pruner_loop, daemon=True).start()
    print(f"pull-svc listening on :{PORT} data={DATA} ttl={PULL_TTL} "
          f"prune_interval={PRUNE_INTERVAL}", flush=True)
    Srv(("0.0.0.0", PORT), H).serve_forever()
