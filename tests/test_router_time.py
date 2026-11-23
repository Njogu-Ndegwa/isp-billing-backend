"""CR-1123-B3: router wall-clock times must never be read as UTC.

The two raw examples come from router 761 on 2026-11-23: its clock ran about
an hour behind EAT, and the assistant layer read its local stamps as UTC, so
past events were told to the reseller as "in 1 h".
"""
from datetime import datetime, timedelta

from app.api import pppoe_monitor
from app.services.assistant.agent import localize_times
from app.services.router_time import read_router_clock, router_time_to_utc, stamp_router_times

TZ = "Africa/Nairobi"


class _ClockApi:
    def __init__(self, date: str, time: str, offset: str = "+03:00"):
        self.row = {"date": date, "time": time, "gmt-offset": offset}

    def send_command(self, path, *args, **kwargs):
        assert path == "/system/clock/print"
        return {"success": True, "data": [self.row]}


def _clock(server_utc: datetime, router_local: datetime):
    api = _ClockApi(router_local.strftime("%Y-%m-%d"), router_local.strftime("%H:%M:%S"))
    return read_router_clock(api, now_utc=server_utc)


def test_diagnose_log_line_becomes_a_past_time_close_to_the_true_one():
    # 15:02 EAT = 12:02 UTC; the router's clock reads 14:02 (an hour slow).
    now = datetime(2026, 11, 23, 12, 2, 0)
    clock = _clock(now, datetime(2026, 11, 23, 14, 2, 0))
    entry = {"time": "2026-11-23 13:22:15", "topics": "pppoe,ppp,info", "message": "ACC20210056: terminating"}
    stamp_router_times(entry, clock)
    assert entry["time_utc"] == "2026-11-23T11:22:15Z"  # 14:22 EAT, the true event

    shown = localize_times(entry, TZ, now=now)
    assert "14:22 EAT" in shown["time_utc"] and "ago" in shown["time_utc"]
    assert "in 1 h" not in str(shown) and "16:22" not in str(shown)
    assert shown["time"].startswith("2026-11-23 13:22:15") and "router" in shown["time"]


def test_users_last_logged_out_becomes_a_past_time_close_to_the_true_one():
    # 14:46 EAT = 11:46 UTC; the router reads 13:46.
    now = datetime(2026, 11, 23, 11, 46, 0)
    clock = _clock(now, datetime(2026, 11, 23, 13, 46, 0))
    user = {"username": "ACC20210056", "online": False, "last_logged_out": "2026-11-23 13:08:00"}
    stamp_router_times({"users": [user]}, clock)
    assert user["last_logged_out_utc"] == "2026-11-23T11:08:00Z"  # 14:08 EAT

    shown = localize_times(user, TZ, now=now)
    assert "14:08 EAT" in shown["last_logged_out_utc"] and "38 min ago" in shown["last_logged_out_utc"]
    assert "in 1 h" not in str(shown) and "16:08" not in str(shown)


def test_ros6_stamps_and_time_only_log_lines():
    now = datetime(2026, 11, 23, 11, 46, 0)
    clock = _clock(now, datetime(2026, 11, 23, 13, 46, 0))
    assert router_time_to_utc("nov/23/2026 13:08:00", clock) == "2026-11-23T11:08:00Z"
    assert router_time_to_utc("13:22:15", clock) == "2026-11-23T11:22:15Z"
    assert router_time_to_utc("jan/01/1970 00:00:00", clock) is None
    assert router_time_to_utc("", clock) is None


def test_unknown_router_clock_is_never_converted_or_put_in_the_future():
    now = datetime(2026, 11, 23, 11, 46, 0)
    user = {"username": "ACC20210056", "last_logged_out": "2026-11-23 13:08:00"}
    stamp_router_times(user, None)
    assert user["last_logged_out_utc"] is None
    shown = localize_times(user, TZ, now=now)
    assert shown["last_logged_out"] == "2026-11-23 13:08:00 (router clock, unverified)"
    assert "in 1 h" not in str(shown)

    entry = {"time": "2026-11-23 13:22:15", "message": "x"}
    stamp_router_times(entry, None)
    shown = localize_times(entry, TZ, now=now)
    assert shown["time"] == "2026-11-23 13:22:15 (router clock, unverified)"


def test_router_clock_more_than_a_day_off_is_not_trusted():
    now = datetime(2026, 11, 23, 11, 46, 0)
    clock = _clock(now, datetime(1970, 1, 2, 0, 5, 0))
    assert router_time_to_utc("1970-01-02 00:01:00", clock) is None


def test_past_event_field_without_router_clock_is_never_annotated_as_future():
    now = datetime(2026, 11, 23, 11, 46, 0)
    # A field the localiser was never told about, holding a router stamp.
    shown = localize_times({"last_seen": "2026-11-23 13:08:00", "last_disconnect_at": "2026-11-23 12:00:00",
                            "expiry": "2026-11-23 13:08:00"}, TZ, now=now)
    assert shown["last_seen"] == "2026-11-23 13:08:00 (router clock, unverified)"
    assert "unverified" in shown["last_disconnect_at"]
    # A real future moment that is not a past-event field still reads as future.
    assert "in 1 h" in shown["expiry"]
    # last_logged_out is always the router's clock, even without a companion.
    shown = localize_times({"last_logged_out": "2026-11-23 10:00:00"}, TZ, now=now)
    assert shown["last_logged_out"] == "2026-11-23 10:00:00 (router clock, unverified)"


def test_past_event_utc_in_the_future_is_flagged():
    now = datetime(2026, 11, 23, 11, 46, 0)
    shown = localize_times({"time_utc": "2026-11-23T13:22:15Z"}, TZ, now=now)
    assert "in 2 h" not in shown["time_utc"] and "router clock, unverified" in shown["time_utc"]


class _FakeRouter:
    """Enough of MikroTikAPI for the PPPoE users and diagnose reads."""

    def __init__(self, *args, **kwargs):
        local = datetime.utcnow() + timedelta(hours=2)  # EAT minus an hour of drift
        self.local = local
        self.stamp = (local - timedelta(minutes=40)).strftime("%Y-%m-%d %H:%M:%S")

    def connect(self):
        return True

    def disconnect(self):
        pass

    def send_command(self, path, *a, **k):
        if path == "/system/clock/print":
            return {"success": True, "data": [{"date": f"{self.local:%Y-%m-%d}", "time": f"{self.local:%H:%M:%S}",
                                               "gmt-offset": "+03:00"}]}
        return {"success": False}

    def get_ppp_secrets_full(self):
        return {"success": True, "data": [{"name": "ACC20210056", "profile": "p", "disabled": False,
                                           "last_logged_out": self.stamp, "last_disconnect_reason": "peer-request"}]}

    def get_pppoe_secret_detail(self, username):
        return {"success": True, "found": True, "data": self.get_ppp_secrets_full()["data"][0]}

    def get_router_logs(self, topics="", limit=50):
        return {"success": True, "data": [{"time": self.stamp, "topics": "pppoe", "message": "ACC20210056: terminating"}]}

    def __getattr__(self, name):
        return lambda *a, **k: {"success": False}


def _close_to_40_min_ago(value):
    when = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    assert abs((datetime.utcnow() - timedelta(minutes=40) - when).total_seconds()) < 120


def test_pppoe_users_and_diagnose_emit_true_utc(monkeypatch):
    monkeypatch.setattr(pppoe_monitor, "MikroTikAPI", _FakeRouter)
    info = {"ip": "10.0.0.1", "username": "u", "password": "p", "port": 8728}

    users = pppoe_monitor._pppoe_users_sync(info)
    _close_to_40_min_ago(users["users"][0]["last_logged_out_utc"])

    diag = pppoe_monitor._pppoe_diagnose_sync(info, "ACC20210056", [])
    _close_to_40_min_ago(diag["info"]["recent_logs"][0]["time_utc"])
    _close_to_40_min_ago(diag["info"]["secret"]["last_logged_out_utc"])

    logs = pppoe_monitor._pppoe_logs_sync(info, "ACC20210056")
    _close_to_40_min_ago(logs["data"][0]["time_utc"])
