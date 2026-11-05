"""PPPoE "share speed across devices" (plan opt-in, off by default).

With the switch on, a login allowed N>1 devices sits on
``pppoe_<rate>_shared_d<N>``: no per-session rate-limit, and on-up/on-down
scripts that keep ONE static ``<pppoe-USER>`` queue at the plan rate whose
target is the login's live session interfaces. With it off, nothing differs
from the per-session behaviour.

The router-side scripts are executed here by a small interpreter for the
subset of RouterOS scripting they use, against a fake router holding PPP
sessions and simple queues, so the 1 / 2 / 4 session targets, the device
limit and the cleanup are checked end to end rather than by string matching.
"""

import asyncio
import re
from datetime import datetime, timedelta

import pytest

from app.db.models import ConnectionType, CustomerStatus
from app.services import fup, mikrotik_background, pppoe_provisioning
from app.services.mikrotik_api import (
    SHARED_SPEED_CLEANUP_SCHEDULER,
    SHARED_SPEED_QUEUE_COMMENT,
    MikroTikAPI,
    is_multi_device_profile,
    multi_device_on_up_script,
    shared_speed_cleanup_on_event,
)
from tests.factories import make_customer, make_plan, make_reseller, make_router


# ---------------------------------------------------------------------------
# A tiny RouterOS script interpreter (only what the profile scripts use)
# ---------------------------------------------------------------------------

class ScriptError(Exception):
    pass


_TOKEN = re.compile(
    r'\s*(?:(?P<str>"(?:[^"\\]|\\.)*")|(?P<var>\$"[^"]+"|\$[A-Za-z0-9_-]+)'
    r'|(?P<punct>[\[\]{}();])|(?P<word>[^\s\[\]{}();"$]+))'
)


def _tokenize(src):
    tokens, pos = [], 0
    while pos < len(src):
        if src[pos:].strip() == "":
            break
        m = _TOKEN.match(src, pos)
        if not m or m.end() == pos:
            raise ScriptError(f"cannot tokenize at {src[pos:pos + 20]!r}")
        pos = m.end()
        kind = m.lastgroup
        text = m.group(kind)
        if kind == "str":
            tokens.append(("str", text[1:-1].replace('\\"', '"')))
        elif kind == "var":
            tokens.append(("var", text[2:-1] if text.startswith('$"') else text[1:]))
        else:
            tokens.append((kind, text))
    return tokens


def _group(tokens, i, close):
    """Return (sub-tokens, index after the matching close)."""
    pairs = {"[": "]", "{": "}", "(": ")"}
    depth, start = 1, i
    while i < len(tokens):
        kind, text = tokens[i]
        if kind == "punct" and text in pairs:
            depth += 1
        elif kind == "punct" and text in pairs.values():
            depth -= 1
            if depth == 0:
                if text != close:
                    raise ScriptError("mismatched brackets")
                return tokens[start:i], i + 1
        i += 1
    raise ScriptError(f"unclosed {close}")


def _items(tokens):
    """Split tokens into items: words, strings, vars and bracket groups."""
    out, i = [], 0
    while i < len(tokens):
        kind, text = tokens[i]
        if kind == "punct" and text in "[{(":
            close = {"[": "]", "{": "}", "(": ")"}[text]
            sub, i = _group(tokens, i + 1, close)
            out.append((text, sub))
            continue
        if kind == "punct" and text in "]})":
            raise ScriptError("unexpected close")
        out.append((kind, text))
        i += 1
    return out


def _statements(tokens):
    stmts, cur, i = [], [], 0
    while i < len(tokens):
        kind, text = tokens[i]
        if kind == "punct" and text in "[{(":
            close = {"[": "]", "{": "}", "(": ")"}[text]
            _sub, j = _group(tokens, i + 1, close)
            cur.extend(tokens[i:j])
            i = j
            continue
        if kind == "punct" and text == ";":
            if cur:
                stmts.append(cur)
            cur = []
        else:
            cur.append(tokens[i])
        i += 1
    if cur:
        stmts.append(cur)
    return stmts


class FakeRouterOS:
    """PPP sessions + simple queues, enough for the shared-speed scripts."""

    def __init__(self):
        self.sessions = []  # {id, user, interface, uptime}
        self.queues = []    # {id, name, target, max-limit, comment, dynamic}
        self.logs = []
        self.pending_down = []
        self._n = 0

    def _id(self):
        self._n += 1
        return f"*{self._n:X}"

    # --- interpreter -----------------------------------------------------
    def run(self, script, env):
        self._block(_tokenize(script), [dict(env)])

    def _block(self, tokens, scopes):
        scopes = scopes + [{}]
        for stmt in _statements(tokens):
            self._stmt(_items(stmt), scopes)

    def _lookup(self, scopes, name):
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
        return None

    def _assign(self, scopes, name, value):
        for scope in reversed(scopes):
            if name in scope:
                scope[name] = value
                return
        raise ScriptError(f":set of undeclared {name}")

    def _value(self, item, scopes):
        kind, val = item
        if kind == "str":
            return val
        if kind == "var":
            return self._lookup(scopes, val)
        if kind == "[":
            return self._stmt(_items(val), scopes)
        if kind == "(":
            return self._expr(_items(val), scopes)
        if kind == "word":
            if val == "true":
                return True
            if val == "false":
                return False
            return int(val) if val.isdigit() else val
        raise ScriptError(f"bad value {item}")

    def _expr(self, items, scopes):
        for ops in ((",",), ("||",), ("=", "!=", ">", "<"), (".",)):
            for idx in range(len(items) - 1, -1, -1):
                kind, val = items[idx]
                if kind == "word" and val in ops:
                    left = self._expr(items[:idx], scopes)
                    right = self._expr(items[idx + 1:], scopes)
                    return self._binop(val, left, right)
        if items and items[0] == ("word", "!"):
            return not self._expr(items[1:], scopes)
        if len(items) == 1 and items[0][0] == "word" and items[0][1].startswith("!"):
            return not self._value(("word", items[0][1][1:]), scopes)
        if len(items) != 1:
            raise ScriptError(f"cannot evaluate {items}")
        return self._value(items[0], scopes)

    @staticmethod
    def _binop(op, a, b):
        if op == ",":
            return (a if isinstance(a, list) else [a]) + (b if isinstance(b, list) else [b])
        if op == "||":
            return bool(a) or bool(b)
        if op == ".":
            return f"{'' if a is None else a}{'' if b is None else b}"
        if op == "=":
            return a == b
        if op == "!=":
            return a != b
        if a is None or b is None:
            return False  # RouterOS compares "nothing" as false, it does not fail
        if op == ">":
            return a > b
        return a < b

    def _kwargs(self, items, scopes):
        """``key=value`` arguments; the value may be a following item."""
        out, i = {}, 0
        while i < len(items):
            kind, val = items[i]
            if kind == "word" and "=" in val:
                key, _, literal = val.partition("=")
                if literal == "" and i + 1 < len(items):
                    out[key] = items[i + 1]
                    i += 2
                    continue
                out[key] = ("word", literal)
            elif kind == "word" and val in ("where", "and"):
                pass
            else:
                out.setdefault("_positional", []).append(items[i])
            i += 1
        return out

    def _stmt(self, items, scopes):
        if not items:
            return None
        kind, head = items[0]
        if kind != "word":
            raise ScriptError(f"statement starts with {items[0]}")
        rest = items[1:]
        if head == ":local":
            scopes[-1][rest[0][1]] = self._value(rest[1], scopes) if len(rest) > 1 else None
            return None
        if head == ":set":
            self._assign(scopes, rest[0][1], self._value(rest[1], scopes))
            return None
        if head == ":if":
            cond = self._value(rest[0], scopes)
            kw = self._kwargs(rest[1:], scopes)
            branch = kw.get("do") if cond else kw.get("else")
            if branch is not None:
                self._block(branch[1], scopes)
            return None
        if head == ":foreach":
            var = rest[0][1]
            kw = self._kwargs(rest[1:], scopes)
            for value in list(self._value(kw["in"], scopes) or []):
                self._block([("word", ":local"), ("word", var), ("str", value), ("punct", ";")]
                            + list(kw["do"][1]), scopes)
            return None
        if head == ":do":
            kw = self._kwargs(rest[1:], scopes)
            try:
                self._block(rest[0][1], scopes)
            except ScriptError:
                if "on-error" in kw:
                    self._block(kw["on-error"][1], scopes)
            return None
        if head == ":log":
            self.logs.append((rest[0][1], self._value(rest[1], scopes)))
            return None
        if head == ":len":
            v = self._value(rest[0], scopes)
            return 0 if v is None else len(v)
        if head == ":pick":
            seq = self._value(rest[0], scopes) or []
            idx = self._value(rest[1], scopes)
            return seq[idx] if idx < len(seq) else None
        if head == ":toarray":
            return []
        if head == ":typeof":
            return "nothing" if self._value(rest[0], scopes) is None else "str"
        if head.startswith("/"):
            path = [head]
            while rest and rest[0][0] == "word" and rest[0][1] in (
                    "active", "pppoe-server", "simple", "find", "get", "add", "set", "remove"):
                path.append(rest[0][1])
                rest = rest[1:]
            return self._command(" ".join(path), rest, scopes)
        raise ScriptError(f"unknown command {head}")

    def _match(self, row, cond, scopes):
        for key, item in cond.items():
            if key == "_positional":
                continue
            if str(row.get(key)) != str(self._value(item, scopes)):
                return False
        return True

    def _command(self, path, rest, scopes):
        kw = self._kwargs(rest, scopes)
        pos = [self._value(p, scopes) for p in kw.get("_positional", [])]
        if path == "/ppp active find":
            return [s["id"] for s in self.sessions if self._match({"name": s["user"]}, kw, scopes)]
        if path == "/ppp active get":
            sess = next(s for s in self.sessions if s["id"] == pos[0])
            return sess[pos[1]]
        if path == "/ppp active remove":
            sess = next((s for s in self.sessions if s["id"] == pos[0]), None)
            if sess is None:
                raise ScriptError("no such item")
            self.sessions.remove(sess)
            self.pending_down.append(sess)
            return None
        if path == "/interface pppoe-server find":
            return [s["id"] for s in self.sessions if self._match({"user": s["user"]}, kw, scopes)]
        if path == "/interface pppoe-server get":
            sess = next(s for s in self.sessions if s["id"] == pos[0])
            return {"name": sess["interface"]}[pos[1]]
        if path == "/queue simple find":
            return [q["id"] for q in self.queues if self._match(q, kw, scopes)]
        if path == "/queue simple add":
            args = {k: self._value(v, scopes) for k, v in kw.items() if k != "_positional"}
            if any(q["name"] == args["name"] for q in self.queues):
                raise ScriptError("queue with such name exists")
            place = args.pop("place-before", "__absent__")
            q = {"id": self._id(), "dynamic": "no", **args,
                 "target": list(args["target"] if isinstance(args["target"], list) else [args["target"]])}
            if place == "__absent__":
                self.queues.append(q)
            else:
                idx = next((i for i, x in enumerate(self.queues) if x["id"] == place), None)
                if idx is None:
                    raise ScriptError("no such item")
                self.queues.insert(idx, q)
            return None
        if path == "/queue simple set":
            ids = pos[0] if isinstance(pos[0], list) else [pos[0]]
            for q in self.queues:
                if q["id"] in ids:
                    if q["dynamic"] == "yes":
                        raise ScriptError("can not change dynamic")
                    for k, v in kw.items():
                        if k != "_positional":
                            val = self._value(v, scopes)
                            q[k] = list(val) if k == "target" else val
            return None
        if path == "/queue simple remove":
            ids = pos[0] if isinstance(pos[0], list) else [pos[0]]
            self.queues = [q for q in self.queues if q["id"] not in ids]
            return None
        raise ScriptError(f"unsupported command {path}")

    # --- PPP events ------------------------------------------------------
    def connect(self, user, profile, uptime=0):
        idx = sum(1 for s in self.sessions if s["user"] == user)
        iface = f"<pppoe-{user}>" if idx == 0 else f"<pppoe-{user}-{idx}>"
        while any(s["interface"] == iface for s in self.sessions):
            idx += 1
            iface = f"<pppoe-{user}-{idx}>"
        sess = {"id": self._id(), "user": user, "interface": iface, "uptime": uptime}
        for s in self.sessions:
            s["uptime"] += 1  # everyone already online is older
        self.sessions.append(sess)
        self.run(profile["on_up"], {"user": user, "interface": iface, "caller-id": iface})
        self._flush_down(profile)
        return iface

    def disconnect(self, interface, profile, *, listed_during_on_down=True):
        sess = next(s for s in self.sessions if s["interface"] == interface)
        if not listed_during_on_down:
            self.sessions.remove(sess)
        self.run(profile["on_down"], {"user": sess["user"], "interface": interface})
        if sess in self.sessions:
            self.sessions.remove(sess)
        self._flush_down(profile)

    def _flush_down(self, profile):
        while self.pending_down:
            sess = self.pending_down.pop(0)
            self.run(profile["on_down"], {"user": sess["user"], "interface": sess["interface"]})

    def queue(self, name):
        return next((q for q in self.queues if q["name"] == name), None)


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def no_headroom(monkeypatch):
    """Plain plan rates in assertions; headroom has its own test below."""
    monkeypatch.setattr(pppoe_provisioning.settings, "PPPOE_RATE_LIMIT_HEADROOM", 1.0, raising=False)


class FakeProfileApi:
    """Records ensure_pppoe_profile / scheduler calls for ensure_plan_pppoe_profile."""

    def __init__(self):
        self.profiles = []
        self.schedulers = 0

    def _parse_speed_to_mikrotik(self, speed):
        return MikroTikAPI._parse_speed_to_mikrotik(self, speed)

    def get_active_pppoe_profile(self):
        return {"found": True, "data": {"local_address": "192.168.89.1", "remote_address": "pppoe-pool"}}

    def ensure_ip_pool(self, name, ranges):
        return {"success": True}

    def ensure_pppoe_profile(self, name, rate_limit, **kwargs):
        self.profiles.append((name, rate_limit, kwargs))
        return {"success": True}

    def ensure_shared_speed_cleanup_scheduler(self):
        self.schedulers += 1
        return {"success": True}


def _shared_profile(max_devices=4, speed="30M/30M"):
    api = FakeProfileApi()
    result = pppoe_provisioning.ensure_plan_pppoe_profile(api, speed, max_devices, True)
    name, rate, kwargs = api.profiles[0]
    return api, result, name, rate, kwargs


def test_shared_profile_has_no_per_session_limit_and_both_scripts():
    api, result, name, rate, kwargs = _shared_profile()

    assert result["profile"] == name == "pppoe_30M_30M_shared_d4"
    assert rate == ""  # no dynamic per-session queue
    assert kwargs["only_one"] == "no"
    assert "max-limit=30M/30M" in kwargs["on_up"]
    assert kwargs["on_down"]
    assert api.schedulers == 1
    # Still a multi-device profile: the only-one=yes re-stamp skips it.
    assert is_multi_device_profile(name)


def test_shared_queue_gets_the_same_headroom_a_session_would(monkeypatch):
    monkeypatch.setattr(pppoe_provisioning.settings, "PPPOE_RATE_LIMIT_HEADROOM", 1.1, raising=False)
    _api, result, _name, _rate, kwargs = _shared_profile()
    assert result["rate_limit"] == "33000000/33000000"
    assert "max-limit=33000000/33000000" in kwargs["on_up"]


def test_switch_off_is_exactly_todays_profile():
    api = FakeProfileApi()
    pppoe_provisioning.ensure_plan_pppoe_profile(api, "30M/30M", 4)
    off = api.profiles[0]
    api2 = FakeProfileApi()
    pppoe_provisioning.ensure_plan_pppoe_profile(api2, "30M/30M", 4, False)

    assert off == api2.profiles[0]
    base = {"local_address": "192.168.89.1", "pool_name": "pppoe-pool", "dns_server": "", "change_tcp_mss": ""}
    assert off == ("pppoe_30M_30M_d4", "30M/30M", {**base, "only_one": "no", "on_up": multi_device_on_up_script(4)})
    assert api.schedulers == api2.schedulers == 0


def test_switch_on_with_one_device_changes_nothing():
    api = FakeProfileApi()
    result = pppoe_provisioning.ensure_plan_pppoe_profile(api, "30M/30M", 1, True)

    assert result["profile"] == "pppoe_30M_30M"
    assert api.profiles[0] == ("pppoe_30M_30M", "30M/30M", {"local_address": "192.168.89.1", "pool_name": "pppoe-pool", "dns_server": "", "change_tcp_mss": ""})
    assert api.schedulers == 0


# ---------------------------------------------------------------------------
# Router behaviour (scripts executed)
# ---------------------------------------------------------------------------

@pytest.fixture
def shared():
    _api, _result, _name, _rate, kwargs = _shared_profile(max_devices=4)
    return kwargs


@pytest.mark.parametrize("sessions", [1, 2, 4])
def test_one_queue_targets_every_session(shared, sessions):
    ros = FakeRouterOS()
    ifaces = [ros.connect("alice", shared) for _ in range(sessions)]

    alice = [q for q in ros.queues if q["name"] == "<pppoe-alice>"]
    assert len(alice) == 1
    assert sorted(alice[0]["target"]) == sorted(ifaces)
    assert alice[0]["max-limit"] == "30M/30M"
    assert alice[0]["comment"] == SHARED_SPEED_QUEUE_COMMENT
    assert ros.logs == []


def test_device_over_the_limit_is_refused_and_queue_keeps_the_others(shared):
    ros = FakeRouterOS()
    ifaces = [ros.connect("alice", shared) for _ in range(4)]

    ros.connect("alice", shared)  # 5th device

    assert len(ros.sessions) == 4
    assert sorted(ros.queue("<pppoe-alice>")["target"]) == sorted(ifaces)


@pytest.mark.parametrize("listed", [True, False])
def test_queue_shrinks_as_sessions_drop_and_goes_with_the_last(shared, listed):
    ros = FakeRouterOS()
    ifaces = [ros.connect("alice", shared) for _ in range(4)]

    ros.disconnect(ifaces[1], shared, listed_during_on_down=listed)
    ros.disconnect(ifaces[3], shared, listed_during_on_down=listed)
    assert sorted(ros.queue("<pppoe-alice>")["target"]) == sorted([ifaces[0], ifaces[2]])

    ros.disconnect(ifaces[0], shared, listed_during_on_down=listed)
    ros.disconnect(ifaces[2], shared, listed_during_on_down=listed)
    assert ros.queue("<pppoe-alice>") is None


def test_other_logins_and_hotspot_queues_are_untouched(shared):
    ros = FakeRouterOS()
    ros.queues.append({"id": "*H1", "name": "plan_AA:BB", "target": ["192.168.88.20/32"],
                       "max-limit": "5M/5M", "comment": "MAC:AA:BB", "dynamic": "no"})
    a = ros.connect("alice", shared)
    b1 = ros.connect("bob", shared)
    b2 = ros.connect("bob", shared)

    assert ros.queue("<pppoe-alice>")["target"] == [a]
    assert sorted(ros.queue("<pppoe-bob>")["target"]) == sorted([b1, b2])

    ros.disconnect(a, shared)
    assert ros.queue("<pppoe-alice>") is None
    assert sorted(ros.queue("<pppoe-bob>")["target"]) == sorted([b1, b2])
    assert ros.queue("plan_AA:BB")["max-limit"] == "5M/5M"


def test_shared_queue_is_placed_first_so_nothing_shadows_it(shared):
    ros = FakeRouterOS()
    ros.queues.append({"id": "*C1", "name": "total", "target": ["ether2"], "max-limit": "100M/100M",
                       "comment": "", "dynamic": "no"})
    ros.connect("alice", shared)
    assert ros.queues[0]["name"] == "<pppoe-alice>"


def test_reboot_cleanup_removes_only_shared_queues(shared):
    ros = FakeRouterOS()
    ros.queues.append({"id": "*H1", "name": "plan_AA:BB", "target": ["192.168.88.20/32"],
                       "max-limit": "5M/5M", "comment": "MAC:AA:BB", "dynamic": "no"})
    ros.connect("alice", shared)
    ros.connect("bob", shared)
    ros.sessions.clear()  # reboot: sessions gone, no on-down ran

    ros.run(shared_speed_cleanup_on_event().replace("[find", "[/queue simple find"), {})
    assert [q["name"] for q in ros.queues] == ["plan_AA:BB"]


def test_fup_throttle_profile_shares_the_throttle_rate():
    calls = []

    class Api:
        connected = True

        def __init__(self, *a, **k):
            pass

        def connect(self):
            return True

        def disconnect(self):
            pass

        def ensure_pppoe_profile(self, name, rate_limit, **kwargs):
            calls.append((name, rate_limit, kwargs))
            return {"success": True}

        def ensure_shared_speed_cleanup_scheduler(self):
            calls.append("scheduler")
            return {"success": True}

        def send_command(self, *a, **k):
            return {"success": True}

        def disconnect_pppoe_session(self, *_a):
            return {"success": True}

    original = fup.MikroTikAPI
    fup.MikroTikAPI = Api
    try:
        info = {"ip": "10.0.0.2", "username": "a", "password": "b", "port": 8728}
        fup._set_secret_throttle_profile_sync(info, "alice", "fup-2M-2M_shared_d4", "2M/2M", 4, True)
    finally:
        fup.MikroTikAPI = original

    name, rate, kwargs = calls[0]
    assert (name, rate) == ("fup-2M-2M_shared_d4", "")
    assert "max-limit=2M/2M" in kwargs["on_up"] and kwargs["on_down"]
    assert calls[1] == "scheduler"


# ---------------------------------------------------------------------------
# App-side cleanup and wiring
# ---------------------------------------------------------------------------

class QueueApi(MikroTikAPI):
    def __init__(self, queues):
        self.connected = True
        self.queues = queues
        self.removed = []
        self.added = []

    def send_command_optimized(self, command, proplist=None, query=None):
        if command == "/queue/simple/print":
            name = (query or "").removeprefix("?name=")
            return {"success": True, "data": [q for q in self.queues if q["name"] == name]}
        if command == "/system/scheduler/print":
            return {"success": True, "data": [{"name": n} for n in self.added]}
        return {"success": True, "data": []}

    def send_command(self, command, args=None):
        if command == "/queue/simple/remove":
            self.removed.append(args["numbers"])
        if command == "/system/scheduler/add":
            self.added.append(args["name"])
            assert args["start-time"] == "startup"
            assert args["on-event"] == shared_speed_cleanup_on_event()
        return {"success": True}


def test_remove_shared_queue_never_touches_a_dynamic_per_session_queue():
    api = QueueApi([
        {".id": "*1", "name": "<pppoe-alice>", "comment": SHARED_SPEED_QUEUE_COMMENT, "dynamic": "false"},
        {".id": "*2", "name": "<pppoe-bob>", "comment": "", "dynamic": "true"},
    ])
    assert api.remove_pppoe_shared_speed_queue("alice") == {"success": True, "removed": 1}
    assert api.remove_pppoe_shared_speed_queue("bob") == {"success": True, "removed": 0}
    assert api.removed == ["*1"]


def test_cleanup_scheduler_is_added_once():
    api = QueueApi([])
    assert api.ensure_shared_speed_cleanup_scheduler()["action"] == "added"
    assert api.ensure_shared_speed_cleanup_scheduler()["action"] == "exists"
    assert api.added == [SHARED_SPEED_CLEANUP_SCHEDULER]


class ProvisionApi:
    instances = []

    def __init__(self, *a, **k):
        self.calls = []
        ProvisionApi.instances.append(self)

    def connect(self):
        return True

    def disconnect(self):
        pass

    def add_pppoe_secret(self, **kwargs):
        self.calls.append(("secret", kwargs["profile"]))
        return {"success": True}

    def ensure_pppoe_fasttrack_bypass(self, pool_name=None):
        self.calls.append(("fasttrack", pool_name))
        return {"success": True}

    def remove_pppoe_shared_speed_queue(self, username):
        self.calls.append(("clear", username))
        return {"success": True}

    def disconnect_pppoe_session(self, username):
        self.calls.append(("kick", username))
        return {"success": True}

    def remove_pppoe_secret(self, username):
        self.calls.append(("remove", username))
        return {"success": True, "action": "removed"}


def _provision(monkeypatch, payload):
    ProvisionApi.instances.clear()
    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", ProvisionApi)
    monkeypatch.setattr(
        pppoe_provisioning, "ensure_plan_pppoe_profile",
        lambda api, bw, n=1, shared=False: {
            "profile": f"p_{n}_{shared}", "base_rate_limit": "30M/30M", "rate_limit": "30M/30M",
            "headroom_factor": 1.0, "pool_name": "pppoe-pool", "profile_result": {},
        },
    )
    base = {"pppoe_username": "alice", "pppoe_password": "x", "bandwidth_limit": "30M/30M",
            "router_ip": "10.0.0.2", "router_username": "a", "router_password": "b", "router_port": 8728}
    result = pppoe_provisioning._provision_pppoe_sync({**base, **payload})
    assert result["success"]
    return ProvisionApi.instances[0].calls


def test_provisioning_puts_shared_logins_on_the_shared_profile_behind_fasttrack_bypass(monkeypatch):
    calls = _provision(monkeypatch, {"max_devices": 4, "shared_speed": True})
    assert calls[0] == ("secret", "p_4_True")
    assert ("fasttrack", "pppoe-pool") in calls  # pool bypass covers the shared queue too
    assert ("clear", "alice") not in calls


def test_switching_off_clears_the_shared_queue_before_the_reconnect(monkeypatch):
    calls = _provision(monkeypatch, {"max_devices": 4, "clear_shared_speed_queue": True})
    assert calls[0] == ("secret", "p_4_False")
    assert calls.index(("clear", "alice")) < calls.index(("kick", "alice"))


def test_plain_provisioning_never_looks_for_a_shared_queue(monkeypatch):
    calls = _provision(monkeypatch, {"max_devices": 4})
    assert ("clear", "alice") not in calls


def test_removing_a_shared_customer_clears_the_queue(monkeypatch):
    ProvisionApi.instances.clear()
    monkeypatch.setattr(pppoe_provisioning, "MikroTikAPI", ProvisionApi)
    base = {"pppoe_username": "alice", "router_ip": "10.0.0.2", "router_username": "a",
            "router_password": "b", "router_port": 8728}

    pppoe_provisioning._remove_pppoe_sync({**base, "shared_speed": True})
    assert ProvisionApi.instances[-1].calls == [("remove", "alice"), ("kick", "alice"), ("clear", "alice")]

    pppoe_provisioning._remove_pppoe_sync(base)
    assert ("clear", "alice") not in ProvisionApi.instances[-1].calls


def test_expiry_cleanup_clears_the_queue_for_shared_customers_only(monkeypatch):
    ProvisionApi.instances.clear()
    monkeypatch.setattr(mikrotik_background, "MikroTikAPI", ProvisionApi)
    info = {"ip": "10.0.0.2", "username": "a", "password": "b", "port": 8728, "name": "R1"}
    customers = [
        {"id": 1, "name": "A", "pppoe_username": "alice", "expiry": None, "router_id": 1, "shared_speed": True},
        {"id": 2, "name": "B", "pppoe_username": "bob", "expiry": None, "router_id": 1},
    ]

    result = mikrotik_background._cleanup_single_router_pppoe_sync(info, customers)

    assert [r["id"] for r in result["removed"]] == [1, 2]
    calls = ProvisionApi.instances[0].calls
    assert ("clear", "alice") in calls
    assert ("clear", "bob") not in calls


async def _plan_with_customers(db, *, shared):
    reseller = await make_reseller(db)
    router = await make_router(db, reseller)
    plan = await make_plan(db, reseller, connection_type=ConnectionType.PPPOE, speed="30M/30M",
                           max_shared_users=4, share_speed_across_devices=shared)
    for username, override in (("alice", None), ("solo", 1)):
        await make_customer(
            db, reseller, plan, router, pppoe_username=username, pppoe_password="x", mac_address=None,
            status=CustomerStatus.ACTIVE, expiry=datetime.utcnow() + timedelta(days=30),
            max_devices_override=override,
        )
    return reseller, plan


@pytest.mark.asyncio
@pytest.mark.parametrize("now_shared", [True, False])
async def test_switch_change_moves_multi_device_customers_only(db, session_factory, monkeypatch, now_shared):
    _reseller, plan = await _plan_with_customers(db, shared=now_shared)
    pushed = []

    async def fake_provision(payload):
        pushed.append(payload)
        return {"success": True}

    monkeypatch.setattr("app.db.database.async_session", session_factory)
    monkeypatch.setattr(pppoe_provisioning, "call_pppoe_provision", fake_provision)

    await pppoe_provisioning.reprovision_plan_pppoe_customers(
        plan.id, speed_changed=False, shared_speed_changed=True,
    )

    assert [p["pppoe_username"] for p in pushed] == ["alice"]  # "solo" has one device
    assert bool(pushed[0].get("shared_speed")) is now_shared
    assert pushed[0]["clear_shared_speed_queue"] is (not now_shared)


@pytest.mark.asyncio
async def test_toggling_the_plan_schedules_the_router_push(db, monkeypatch):
    from app.api import plan_routes

    reseller, plan = await _plan_with_customers(db, shared=False)
    scheduled = []

    async def fake_push(plan_id, *, speed_changed, shared_speed_changed=False):
        scheduled.append((speed_changed, shared_speed_changed))
        return {}

    async def fake_current_user(_token, _db):
        return reseller

    async def no_cache():
        return None

    monkeypatch.setattr(plan_routes, "get_current_user", fake_current_user)
    monkeypatch.setattr(plan_routes, "enforce_active_subscription", lambda _user: None)
    monkeypatch.setattr(plan_routes, "invalidate_plan_cache", no_cache)
    monkeypatch.setattr(pppoe_provisioning, "reprovision_plan_pppoe_customers", fake_push)

    async def update(**fields):
        response = await plan_routes.update_plan_api(
            plan.id, plan_routes.PlanUpdateRequest(**fields), db=db, token="token",
        )
        await asyncio.sleep(0)
        return response

    response = await update(share_speed_across_devices=True)
    assert response["share_speed_across_devices"] is True
    await update(share_speed_across_devices=True)  # no change: no push
    await update(price=999)
    await update(share_speed_across_devices=False)

    assert scheduled == [(False, True), (False, True)]


def test_payloads_carry_the_switch_only_when_on():
    class Plan:
        speed = "30M/30M"
        max_shared_users = 4
        share_speed_across_devices = False

    class Customer:
        id = 7
        name = "Alice"
        phone = "254700000000"
        pppoe_username = "alice"
        pppoe_password = "secret"
        max_devices_override = None
        plan = Plan()

    class Router:
        ip_address = "10.0.0.2"
        username = "admin"
        password = "x"
        port = 8728

    assert "shared_speed" not in pppoe_provisioning.build_pppoe_payload(Customer(), Router())
    assert "shared_speed" not in pppoe_provisioning.build_pppoe_remove_payload(Customer(), Router())
    Plan.share_speed_across_devices = True
    assert pppoe_provisioning.build_pppoe_payload(Customer(), Router())["shared_speed"] is True
    assert pppoe_provisioning.build_pppoe_remove_payload(Customer(), Router())["shared_speed"] is True
