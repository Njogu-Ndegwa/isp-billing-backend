# WAN port reported as a silent access link

Hassan router 606's dashboard showed `1 port warning: ether2` after dual-WAN
recovery. Live checks found both DHCP leases bound, both ports at 1 Gbps full
duplex with zero errors/drops, and WAN2 receiving 76 Mbps with 2,268 replied
connections. The analytics response nevertheless called both WANs silent:
`Link is up but no downstream MACs are currently learned`.

The shared live/push analyzer applied bridge MAC learning to routed WANs. The
frontend only hid this warning for unbridged ether1, leaving ether2 visible.

The analytics endpoint now passes the existing LB configuration into the shared
analyzer. An enabled, configured WAN that is unbridged and link-up is active
without learned customer MACs. Interface errors still warn, and a configured WAN
with no physical link warns explicitly. Bridged ports and disabled/unconfigured
LB retain existing access-port diagnostics. This reports physical port health;
it does not claim that link-up alone proves upstream internet reachability.

Regression tests cover live and push input, WAN errors and link loss, disabled
LB, other access ports, stale configuration pointing at a bridge, and endpoint
configuration propagation. No router configuration or frontend changes are
required to remove the false warning.
