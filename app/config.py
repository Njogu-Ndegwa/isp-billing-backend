from pydantic_settings import BaseSettings
from dotenv import load_dotenv


load_dotenv()  # Optional if you use a .env file

class Settings(BaseSettings):
    # A restored migration/DR stack must be safe to start alongside production.
    # Shadow mode makes application DB connections read-only, skips startup
    # migrations/schedulers, blocks unsafe HTTP methods, and guards outbound
    # router/provider mutation boundaries.
    SHADOW_MODE: bool = False
    # Allow startup migrations while keeping a dark migration candidate from
    # launching fleet scans, payment reconciliation, notifications, or other
    # scheduled work. Production defaults to enabled; deployment candidates
    # must opt out explicitly until traffic ownership is transferred.
    SCHEDULER_ENABLED: bool = True

    # PostgreSQL connection - set via environment variable
    DATABASE_URL: str = "postgresql+asyncpg://isp_user:isp_secure_pass_2024@localhost:5434/isp_billing_db"
    # Real-time push pilot (2026-09-25). Comma-separated router ids that report
    # every REALTIME_PUSH_INTERVAL_SECONDS with the v2 payload (hosts, queue
    # targets, router health), are metered per device from /ip hotspot host
    # instead of per queue, and get their queues repaired as soon as a report
    # shows a problem. Every other router keeps today's behaviour.
    # 10 = Bitwave Wangige, 487 = OPIC INTERNET SERVICES #2 (hotspot + PPPoE),
    # 351 / 390 / 426 = reseller "aayan" (RB951 / hAP lite / hAP lite).
    # Canaries 2026-09-25: 224 (RB951, ROS 6.49), 163 (RB951, 7.20),
    # 521 (RB951, 7.24), 478 (hAP lite, 6 MB free RAM).
    REALTIME_PILOT_ROUTER_IDS: str = "10,487,351,390,426,224,163,521,478"
    # Uniform cadence for every pilot router (Dennis, 2026-09-25). Over the
    # management tunnel a hAP lite at ~60 s ran at ~19% CPU against a 14% baseline.
    REALTIME_PUSH_INTERVAL_SECONDS: int = 60
    # Per-router cadence, "id:seconds,...". Measured 2026-09-25 on hAP lite 390
    # (ROS 6.49.6): one v2 run takes ~11 s and pins the CPU at 100% (HTTPS on
    # smips); at 30 s the average went 12% -> 41%, at 60 s to 51%. Small boards
    # therefore stay at 120 s, the cost of today's standard push. Every router
    # also backs off on its own reported CPU.
    # Applies to HTTPS reports only: over the management tunnel (plain HTTP
    # inside WireGuard / L2TP-IPsec, no TLS on the router) a report costs a
    # hAP lite ~1-2 s, so tunnel reports get the base cadence.
    REALTIME_PUSH_INTERVAL_OVERRIDES: str = "351:120,390:120,426:120"
    # Where pilot routers post when their tunnel reaches this server. Port
    # 8088, not 80: routers carry ISP_BILLING_PROXY_RELAY_BLOCK, which rejects
    # the router's own outbound tcp 80/3128/8080 to non-portal hosts (hotspot
    # bypass fix) and must stay. Caddy binds 8088 on the tunnel address only.
    REALTIME_TUNNEL_PUSH_URL: str = "http://10.251.0.1:8088/api/router/usage-push"
    # Router expiry reaper (app/services/expiry_reaper_script.py): tried in this
    # order. The tunnel one is plain HTTP inside the management tunnel (Caddy's
    # 10.251.0.1:8088 site); public HTTPS costs a hAP lite ~5-7 s of full CPU.
    EXPIRY_REAPER_TUNNEL_URL: str = "http://10.251.0.1:8088/api/router/expiry-check"
    EXPIRY_REAPER_PUBLIC_URL: str = "https://isp.bitwavetechnologies.net/api/router/expiry-check"
    # Router check-in delivery pilot (2026-09-26). The router POSTs the MACs of
    # its app-tagged bypass bindings to /api/router/checkin; the server answers
    # with the paid MACs it is missing. Off by default, and only routers listed
    # in CHECKIN_ROUTER_IDS ("12,47") are ever answered with work.
    # CHECKIN_MODE: "shadow" = compute + log what would be sent, reply with
    # nothing; "add" = reply with add lines. Removals are never sent (pilot).
    # CHECKIN_KILL_SWITCH makes every reply an empty idle frame, which also
    # reaches routers whose management tunnel is down.
    CHECKIN_ENABLED: bool = False
    CHECKIN_ROUTER_IDS: str = ""
    CHECKIN_MODE: str = "shadow"
    CHECKIN_KILL_SWITCH: bool = False
    CHECKIN_MAX_LINES_PER_REPLY: int = 10
    # A paid MAC must be missing from the router's report for at least this
    # long, across check-ins, before an add line is offered. Covers the
    # Reconnect race (2026-09-26): the app removes the OLD MAC's binding a few
    # seconds before the customer row switches to the NEW MAC, and a check-in
    # in that gap must not re-add the OLD MAC as an orphan binding.
    CHECKIN_MISSING_GRACE_SECONDS: int = 60
    DB_POOL_SIZE: int = 15
    DB_MAX_OVERFLOW: int = 15
    DB_POOL_TIMEOUT: int = 10
    DB_POOL_RECYCLE_SECONDS: int = 1800
    # Per-connection guardrails against lock convoys / wedged transactions.
    # Postgres auto-aborts any app session left idle-in-transaction past this,
    # releasing its locks + pooled connection; and a writer gives up after
    # DB_LOCK_TIMEOUT_MS instead of pinning a connection while it waits.
    # Scoped to the app's connections only (does not affect FreeRADIUS).
    # 60s (not 30s): comfortably covers the synchronous M-Pesa STK-push API
    # handshake — two payment endpoints hold a tx across it — while still being
    # ~43x tighter than the wedge this guards against. See incident note.
    DB_IDLE_TX_TIMEOUT_MS: int = 60000
    DB_LOCK_TIMEOUT_MS: int = 5000
    # Local billing calendar offset from UTC. Everything is stored in UTC, but
    # "today" on a dashboard means the local calendar day (00:00 EAT -> now),
    # not a rolling 24h window. Kenya/EAT = UTC+3 and has no DST.
    LOCAL_UTC_OFFSET_HOURS: int = 3
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    # MikroTik Configuration (via WireGuard VPN)
    MIKROTIK_HOST: str = "10.0.0.2"  # MikroTik IP over WireGuard VPN
    MIKROTIK_PORT: int = 8728
    MIKROTIK_USERNAME: str = "admin"
    MIKROTIK_PASSWORD: str = "mvnm"  # Set in .env file
    PPPOE_RATE_LIMIT_HEADROOM: float = 1.08
    # Max compensation (zero-revenue) vouchers a reseller may issue per UTC day.
    COMPENSATION_DAILY_LIMIT: int = 10
    # Longest power-outage window a single bulk compensation run may credit.
    # Fat-finger guard: a mistyped year-long window would hand everyone a year
    # of free time. Genuinely longer outages = multiple runs.
    OUTAGE_COMPENSATION_MAX_HOURS: int = 72
    # Rows the preview ships for display. Totals are always computed over
    # everyone; this only bounds the payload sent to the browser.
    OUTAGE_COMPENSATION_PREVIEW_ROWS: int = 500

    # M-Pesa Configuration
    MPESA_CONSUMER_KEY: str
    MPESA_CONSUMER_SECRET: str
    MPESA_SHORTCODE: str
    MPESA_PASSKEY: str
    MPESA_CALLBACK_URL: str
    MPESA_ENVIRONMENT: str

    # M-Pesa B2B (Business-to-Business) Payouts
    MPESA_B2B_INITIATOR_NAME: str = ""
    MPESA_B2B_INITIATOR_PASSWORD: str = ""
    MPESA_B2B_SECURITY_CREDENTIAL: str = ""
    MPESA_B2B_RESULT_URL: str = ""
    MPESA_B2B_TIMEOUT_URL: str = ""
    MPESA_B2B_STATUS_RESULT_URL: str = ""
    MPESA_B2B_STATUS_TIMEOUT_URL: str = ""
    MPESA_B2B_DAILY_PAYOUT_ENABLED: bool = False

    # A parallel standby must never run billing, payment reconciliation, or
    # router-maintenance jobs while the production instance is active.
    RUN_SCHEDULER: bool = True

    # Router Auto-Provisioning
    SERVER_PUBLIC_IP: str = ""
    WG_MANAGER_URL: str = "http://host.docker.internal:8729"
    WG_MANAGER_SECRET: str = "change-me-wg-secret"
    PROVISION_BASE_URL: str = "https://isp.bitwavetechnologies.net"
    # RouterOS v6 often cannot complete a TLS handshake with modern CDN edges.
    # When set, L2TP/v6 provisioning fetches scripts from this URL instead of
    # PROVISION_BASE_URL. Leave blank to auto-downgrade https://... to http://...
    # for v6 bootstrap only.
    PROVISION_LEGACY_BASE_URL: str = ""
    L2TP_IPSEC_PSK: str = "BitwaveL2TP2026!Secure"

    # Access credential idle reaper: minutes a bound MAC can be unseen on the
    # router's hotspot host table before the credential is auto-released so
    # another device can use it.
    ACCESS_CRED_IDLE_RELEASE_MINUTES: int = 15

    # Secondary/insurance WireGuard endpoint. The old app can use these values
    # to add a backup tunnel to an existing router while normal operations keep
    # using the current 10.0.0.0/16 management network.
    INSURANCE_WG_MANAGER_URL: str = ""
    INSURANCE_WG_MANAGER_SECRET: str = ""
    INSURANCE_SERVER_PUBLIC_IP: str = ""
    INSURANCE_SERVER_WG_PUBLIC_KEY: str = ""
    INSURANCE_SERVER_VPN_IP: str = "10.250.0.1"
    INSURANCE_WG_PORT: int = 51821
    INSURANCE_ROUTER_INTERFACE: str = "wg-aws2"
    INSURANCE_WG_SUBNET: str = "10.250.0.0/16"
    INSURANCE_L2TP_INTERFACE: str = "l2tp-aws2"
    INSURANCE_L2TP_IPSEC_PSK: str = ""
    INSURANCE_MANAGER_TIMEOUT: int = 10

    # --- Messaging / SMS -------------------------------------------------
    SMS_PROVIDER: str = "talksasa"
    SMS_SENDER_ID: str = "TALKSASA"
    AT_USERNAME: str = ""
    AT_API_KEY: str = ""
    AT_SENDER_ID: str = ""
    AT_BASE_URL: str = "https://api.africastalking.com"
    TALKSASA_API_TOKEN: str = ""
    TALKSASA_SENDER_ID: str = "TALKSASA"
    TALKSASA_BASE_URL: str = "https://bulksms.talksasa.com/api/v3"
    SMS_DISPATCH_CHUNK_SIZE: int = 100
    SMS_DISPATCH_ENABLED: bool = True
    # Router overload alerts to resellers (app/services/router_overload_alerts.py).
    # Payment-failure signal needs no router access and is on by default; the
    # SNMP CPU poll stays off until routers are enrolled with
    # scripts/router_snmp_rollout.py and a community is configured.
    ROUTER_OVERLOAD_ALERTS_ENABLED: bool = True
    ROUTER_SNMP_POLL_ENABLED: bool = False
    ROUTER_SNMP_COMMUNITY: str = ""

    # --- Feedback board (Ideas + Bugs) / AI triage -----------------------
    # ANTHROPIC_API_KEY lives in the server .env only — never committed.
    # Empty key = AI features degrade gracefully to manual triage.
    ANTHROPIC_API_KEY: str = ""
    FEEDBACK_AI_ENABLED: bool = True
    FEEDBACK_TRIAGE_MODEL: str = "claude-opus-4-8"
    FEEDBACK_REPLY_MODEL: str = "claude-opus-4-8"
    FEEDBACK_DAILY_POST_CAP: int = 15

    # --- Transactional email (password reset) ----------------------------
    # Credentials live in the server .env only — never committed.
    # SMTP is preferred when SMTP_HOST is set (e.g. smtp.gmail.com + app
    # password); otherwise Resend is used if RESEND_API_KEY is set. With
    # neither configured, reset emails are skipped and logged; the
    # forgot-password endpoint still returns its generic response.
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_SSL: bool = False  # False = STARTTLS on 587; True = implicit TLS on 465
    RESEND_API_KEY: str = ""
    RESEND_BASE_URL: str = "https://api.resend.com"
    EMAIL_FROM: str = "Bitwave Technologies <noreply@bitwavetechnologies.com>"
    # Base URL of the admin frontend, used to build password reset links.
    FRONTEND_BASE_URL: str = "https://bitwavetechnologies.com"
    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = 60

    # Card payments for subscriptions (PayAfrica -> Paystack hosted checkout).
    PAYAFRICA_BASE_URL: str = "https://api.payafrica.org"
    # Public base URL PayAfrica calls when a card payment succeeds. Must be a
    # destination PayAfrica has registered; empty disables sending webhook_url.
    PAYAFRICA_WEBHOOK_BASE_URL: str = "https://isp.bitwavetechnologies.net"

    # Just-in-time RouterOS operator access. This is the source allowed to
    # reach WinBox/SSH/WebFig when an admin opens remote access for a router.
    ROUTER_REMOTE_ACCESS_SOURCE_CIDRS: str = "10.0.0.1/32"
    ROUTER_WEBFIG_SESSION_MINUTES: int = 120
    ROUTER_WEBFIG_PROXY_TIMEOUT_SECONDS: int = 20

    # --- Operations health monitor (app/services/ops_health.py) ------------
    # Optional JSON written by ops/native-router-route-sync.py on the tunnel
    # host: {"checked_at": iso, "native": n, "transit_fallback": n, "unrouted": n}.
    # Empty = the control-path tile reports available=false.
    OPS_ROUTE_STATE_FILE: str = ""
    # Critical-only SMS destination for ops alerts. Empty = inbox alerts only.
    OPS_ALERT_SMS_PHONE: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
