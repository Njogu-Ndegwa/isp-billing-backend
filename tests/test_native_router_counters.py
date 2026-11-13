import copy
import unittest
from datetime import datetime, timezone

from app.services import native_router_counters as codec


def sample():
    return {
        "hosts": [
            {
                " .unused": "",
                ".id": "*A",
                "mac-address": "02:BC:56:30:00:00",
                "address": "198.18.57.10",
                "to-address": "192.168.88.254",
                "authorized": "true",
                "bypassed": "false",
                "bytes-in": "9007199254740993",
                "bytes-out": "42",
                "idle-time": "0s",
                "uptime": "1m",
            }
        ],
        "interfaces": [
            {
                ".id": "*1",
                "name": "ether1",
                "type": "ether",
                "running": "true",
                "disabled": "false",
                "rx-byte": "9007199254740995",
                "tx-byte": "64",
                "rx-packet": "7",
                "tx-packet": "8",
                "rx-error": "0",
                "tx-error": "0",
                "link-downs": "1",
            }
        ],
        "resource": [
            {
                "cpu-load": "4",
                "free-memory": "64000000",
                "total-memory": "128000000",
                "free-hdd-space": "100000000",
                "total-hdd-space": "128000000",
                "uptime": "1h2m",
                "version": "7.19.6",
                "board-name": "RB951Ui-2HnD",
            }
        ],
        "queues": [
            {
                ".id": "*10",
                "name": "plan_02BC56300000",
                "bytes": "100/200",
                "target": "198.18.57.10/32",
                "max-limit": "1000000/1000000",
                "disabled": "false",
            },
            {
                ".id": "*11",
                "name": "<pppoe-alice>",
                "bytes": "300/400",
                "target": "10.10.0.2/32",
                "max-limit": "2000000/2000000",
                "disabled": "false",
            },
        ],
        "ppp": [],
        "bridge_hosts": [
            {
                ".id": "*1",
                "mac-address": "02:BC:56:30:00:00",
                "on-interface": "ether2",
                "local": "false",
            },
            {
                ".id": "*2",
                "mac-address": "04:F4:1C:CA:8D:2B",
                "on-interface": "ether2",
                "local": "true",
            },
        ],
        "bindings": [],
        "leases": [],
        "neighbors": [],
        "bridge_ports": [],
    }


class NativeApiContractTests(unittest.TestCase):
    def test_observation_times_follow_host_keys_and_reordered_queues(self):
        when = datetime(2026, 10, 20, 1, 0, tzinfo=timezone.utc)
        body = self.decode(
            queue_order=["*11", "*10"],
            observed={
                "hosts": {"*A": when},
                "queues": {"*10": when, "*11": when},
            },
        )
        self.assertEqual(body["hosts"][0]["sampled_at"], when.isoformat())
        self.assertTrue(
            all(r["sampled_at"] == when.isoformat() for r in body["reports"])
        )
        self.assertEqual(body["router"]["wan_link_downs"], 1)

    def decode(self, tables=None, **kwargs):
        return codec.native_api_to_v3("Bench", tables or sample(), "ether1", **kwargs)

    def test_exact_integer_and_original_host_address_domain(self):
        body = self.decode()
        self.assertEqual(body["v"], 3)
        self.assertEqual(body["hosts"][0]["bytes_in"], 9007199254740993)
        self.assertEqual(body["router"]["iface_rx_bytes"], 9007199254740995)
        self.assertEqual(body["hosts"][0]["ip"], "198.18.57.10")
        self.assertTrue(body["hosts"][0]["authorized"])
        self.assertFalse(body["hosts"][0]["bypassed"])

    def test_queue_priority_and_native_limits_are_preserved(self):
        body = self.decode(queue_order=["*11", "*10"])
        self.assertEqual(
            [q["queue_key"] for q in body["reports"]], ["pppoe:alice", "02BC56300000"]
        )
        self.assertEqual(body["reports"][1]["max_limit"], "1000000/1000000")
        self.assertFalse(body["reports"][1]["disabled"])

    def test_duplicate_same_host_counter_is_rejected(self):
        tables = sample()
        other = copy.deepcopy(tables["hosts"][0])
        other[".id"] = "*B"
        tables["hosts"].append(other)
        with self.assertRaisesRegex(ValueError, "duplicate native host"):
            self.decode(tables)

    def test_two_addresses_of_same_mac_remain_separate_counters(self):
        tables = sample()
        other = copy.deepcopy(tables["hosts"][0])
        other[".id"] = "*B"
        other["address"] = "198.18.57.11"
        tables["hosts"].append(other)
        self.assertEqual(len(self.decode(tables)["hosts"]), 2)

    def test_unpaid_host_is_excluded_from_metering(self):
        tables = sample()
        tables["hosts"][0]["authorized"] = "false"
        body = self.decode(tables)
        self.assertEqual(body["hosts"], [])
        self.assertEqual(body["router"]["hotspot_active"], 0)

    def test_vanishing_queue_does_not_invent_zero_counters(self):
        tables = sample()
        del tables["queues"][0]["bytes"]
        self.assertEqual(
            [q["queue_key"] for q in self.decode(tables)["reports"]], ["pppoe:alice"]
        )

    def test_empty_inventory_and_missing_optional_link_time(self):
        body = self.decode()
        self.assertEqual(body["bindings"], [])
        self.assertEqual(body["leases"], [])
        self.assertEqual(body["ports"][0]["last_link_up"], "")
        self.assertEqual(len(body["bridge_hosts"]), 1)

    def test_uncollected_inventory_is_omitted_without_changing_billing(self):
        tables = sample()
        complete = self.decode(tables)
        for name in ("bridge_hosts", "bindings", "leases", "neighbors", "bridge_ports"):
            tables.pop(name, None)
        body = self.decode(tables)
        for name in ("bridge_hosts", "bindings", "leases", "neighbors", "bridge_ports"):
            self.assertNotIn(name, body)
        for name in ("hosts", "reports", "ppp", "ports", "router"):
            self.assertEqual(body[name], complete[name])

    def test_negative_counter_and_invalid_flag_fail_closed(self):
        tables = sample()
        tables["hosts"][0]["bytes-in"] = "-1"
        with self.assertRaises(ValueError):
            self.decode(tables)
        tables = sample()
        tables["hosts"][0]["authorized"] = "not-a-flag"
        with self.assertRaises(ValueError):
            self.decode(tables)


if __name__ == "__main__":
    unittest.main()
