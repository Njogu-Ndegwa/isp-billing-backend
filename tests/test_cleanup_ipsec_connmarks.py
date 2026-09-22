from scripts.cleanup_ipsec_connmarks import parse_rules, superseded_rules


def test_connmark_cleanup_keeps_first_rule_for_each_exact_tuple():
    rules = parse_rules(
        """
-A PREROUTING -s 203.0.113.4/32 -d 172.20.0.2/32 -p udp -m udp --sport 4500 --dport 4500 -j MARK --set-xmark 0x3/0xffffffff
-A PREROUTING -s 203.0.113.4/32 -d 172.20.0.2/32 -p udp -m udp --sport 4500 --dport 4500 -j MARK --set-xmark 0x2/0xffffffff
-A PREROUTING -s 203.0.113.4/32 -d 172.20.0.2/32 -p udp -m udp --sport 4501 --dport 4500 -j MARK --set-xmark 0x4/0xffffffff
"""
    )

    stale = superseded_rules(rules)

    assert len(rules) == 3
    assert [rule.line for rule in stale] == [rules[1].line]
