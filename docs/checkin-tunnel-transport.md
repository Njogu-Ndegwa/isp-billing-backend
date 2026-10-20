# Check-in transport pilot

The existing management-tunnel listener forwards usage and expiry reports, but
its matcher also needs `/api/router/checkin` before check-in can use it. A 404
from that listener is a missing route, not an authentication failure.

`CHECKIN_TUNNEL_ROUTER_IDS` is empty by default. For explicitly selected routers,
the standard installer passes `CHECKIN_TUNNEL_ENDPOINT_URL` to the renderer.
This selection does not enroll a router for check-in or override the existing
small-board policy. The manual pilot installer also accepts
`CHECKIN_TUNNEL_URL` for a scoped installation.

The tunnel URL must be a literal IPv4 address in 10/8, use HTTP port 8088, and
have exactly the check-in path. Deploy only on a reviewed encrypted management
path. The listener must remain bound to the tunnel address and restricted to
tunnel source addresses. Keep the same check-in token authentication.

The tunnel attempt uses a three-second idle timeout and five-second duration
limit. A failed attempt falls back to the existing public fetch with its
certificate policy unchanged. Both responses still pass through the complete
existing frame validator before any command can run. A successful HTTP response
with an invalid frame applies nothing, following the existing behavior.

`prefer_tunnel_transport` can wrap the current installed source without
regenerating its identity, token, gate, or command logic. It refuses unexpected
fetch shapes and a conflicting existing transport wrapper. The default
renderer remains unchanged until the transport is explicitly selected.

Before enrollment, validate the listener configuration and test the healthy
tunnel path, unavailable tunnel/public fallback, and rejection of malformed
frames on the spare. Then measure a scoped live canary, preserving source
backups and an automatic rollback. Unit tests establish source and selection
contracts; they do not establish a CPU ceiling or RouterOS 6 hardware support.


Validated 2026-10-20 on the home RB951 (563, RouterOS 7.19.6) and CJ
(597, 7.24.2): each completed two scheduled, fully validated tunnel replies
with no public fallback. The private Caddy route is active and still rejects
unauthenticated requests. A separate home trial completed two public fallbacks
when that route was unavailable. Original source backups are retained.

This removes TLS work, but does not establish a CPU ceiling: the 200-session
home test still saturated while building inventory and processing the reply,
even with HTTP over the tunnel. Native configuration events are being tested
as the replacement for that recurring script work.
