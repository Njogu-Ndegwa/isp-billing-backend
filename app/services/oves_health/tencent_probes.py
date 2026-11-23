"""Tencent Cloud dependencies (TKE ``oves-dev`` cls-4j425vg2, ap-singapore).

Since the 2026-10-08 Cloudflare change, PRODUCTION traffic depends on this
"dev" cluster: the MQTT broker every device talks to, the wvapp web layer the
oves-app shell loads, ABS (real payments credit quota there) and the DIRAC
portal API. Treat those as production.
"""

from __future__ import annotations

from app.services.oves_health.probes import Probe

P = Probe
# The ingress-nginx load balancer every Tencent web app sits behind (Cloudflare
# proxies to it). Cloudflare's Paris edge, which this monitor's Nuremberg box
# uses, intermittently hangs on the way to it while other edges and the origin
# itself answer (found 2026-11-23), so web probes double-check the origin.
TENCENT_INGRESS = "lb-hssiqwrq-0ohgrlzi8m92qsa5.clb.sg-tencentclb.com"
TENCENT_PROBES: list[Probe] = [
    P("mqtt_broker", "MQTT broker + auth (EMQX, production)", "tencent", "mqtt_connect",
      "mqtt.omnivoltaic.com:1883",
      "All device telemetry + code delivery (ble-app hard-codes 1883)", critical=True),
    P("mqtt_8883", "MQTT TLS :8883", "tencent", "tcp", "mqtt.omnivoltaic.com:8883",
      "TLS devices (chain is self-signed: known defect)"),
    # Since ble-app #25 (2026-11-09) portal.omnivoltaic.com is the app's address and
    # wvapp.omnivoltaic.com answers page loads with a 307 to it, so the app check
    # targets portal (the id stays "wvapp" for the dashboard) and a second check
    # makes sure the old address, which older oves-app installs still open, keeps redirecting.
    P("wvapp", "Field app web layer (portal.omnivoltaic.com)", "tencent", "http",
      "https://portal.omnivoltaic.com/",
      "Every field-staff applet in oves-app", expect_text="/_next/static/", critical=True,
      origin=TENCENT_INGRESS),
    P("wvapp_legacy", "wvapp.omnivoltaic.com redirect", "tencent", "http",
      "https://wvapp.omnivoltaic.com/",
      "Older oves-app installs start here", expect_status=(307, 308)),
    P("abs_dev", "ABS platform", "tencent", "http",
      "https://abs-platform-dev.omnivoltaic.com/graphql",
      "ble-app identify / serviceTopup, rider activity", method="POST",
      body={"query": "{__typename}"}, expect_text="Query", critical=True,
      origin=TENCENT_INGRESS),
    P("dirac_portal", "DIRAC portal API", "tencent", "http",
      "https://dirac-fed-dev.omnivoltaic.com/odoo-portal",
      "portal.omnivoltaic.com, ble-app portal client", method="POST",
      body={"query": "{__typename}"}, expect_text="__typename", critical=True,
      origin=TENCENT_INGRESS),
    P("dev_gateway_login", "Dev gateway login", "tencent", "login",
      "https://dev-federated-graphql-api.omnivoltaic.com/graphql",
      "ble-app on non-wvapp origins, ERM preview"),
    # tencent_mongo and tencent_postgres were removed on 2026-11-20: their public CLBs
    # (mongo-N.dev.global, dev.postgres.global) were closed. Mongo health is still
    # covered by mqtt_broker (EMQX authenticates every device against it) and
    # dev_gateway_login; exposed_tencent_mongo now checks the port stays closed.
    P("memo_cos", "Memo / deck site (COS + EdgeOne)", "tencent", "http",
      "https://memo.omnivoltaic.cn/", "Company memos", expect_status=(401,)),
]
