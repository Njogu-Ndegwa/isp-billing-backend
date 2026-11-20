"""Tencent Cloud dependencies (TKE ``oves-dev`` cls-4j425vg2, ap-singapore).

Since the 2026-10-08 Cloudflare change, PRODUCTION traffic depends on this
"dev" cluster: the MQTT broker every device talks to, the wvapp web layer the
oves-app shell loads, ABS (real payments credit quota there) and the DIRAC
portal API. Treat those as production.
"""

from __future__ import annotations

from app.services.oves_health.probes import Probe

P = Probe
TENCENT_PROBES: list[Probe] = [
    P("mqtt_broker", "MQTT broker + auth (EMQX, production)", "tencent", "mqtt_connect",
      "mqtt.omnivoltaic.com:1883",
      "All device telemetry + code delivery (ble-app hard-codes 1883)", critical=True),
    P("mqtt_8883", "MQTT TLS :8883", "tencent", "tcp", "mqtt.omnivoltaic.com:8883",
      "TLS devices (chain is self-signed: known defect)"),
    P("wvapp", "wvapp (field app web layer)", "tencent", "http", "https://wvapp.omnivoltaic.com/",
      "Every field-staff applet in oves-app", expect_text="/_next/static/", critical=True),
    P("abs_dev", "ABS platform", "tencent", "http",
      "https://abs-platform-dev.omnivoltaic.com/graphql",
      "ble-app identify / serviceTopup, rider activity", method="POST",
      body={"query": "{__typename}"}, expect_text="Query", critical=True),
    P("dirac_portal", "DIRAC portal API", "tencent", "http",
      "https://dirac-fed-dev.omnivoltaic.com/odoo-portal",
      "portal.omnivoltaic.com, ble-app portal client", method="POST",
      body={"query": "{__typename}"}, expect_text="__typename", critical=True),
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
