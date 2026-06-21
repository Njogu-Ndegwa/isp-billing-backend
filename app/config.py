from pydantic_settings import BaseSettings
from dotenv import load_dotenv


load_dotenv()  # Optional if you use a .env file

class Settings(BaseSettings):
    # PostgreSQL connection - set via environment variable
    DATABASE_URL: str = "postgresql+asyncpg://isp_user:isp_secure_pass_2024@localhost:5434/isp_billing_db"
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
    MPESA_B2B_DAILY_PAYOUT_ENABLED: bool = False

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
    SMS_PROVIDER: str = "africastalking"
    SMS_SENDER_ID: str = ""
    AT_USERNAME: str = ""
    AT_API_KEY: str = ""
    AT_SENDER_ID: str = ""
    AT_BASE_URL: str = "https://api.africastalking.com"
    TALKSASA_API_TOKEN: str = ""
    TALKSASA_SENDER_ID: str = ""
    TALKSASA_BASE_URL: str = "https://bulksms.talksasa.com/api/v3"
    SMS_DISPATCH_CHUNK_SIZE: int = 100
    SMS_DISPATCH_ENABLED: bool = True

    # Just-in-time RouterOS operator access. This is the source allowed to
    # reach WinBox/SSH/WebFig when an admin opens remote access for a router.
    ROUTER_REMOTE_ACCESS_SOURCE_CIDRS: str = "10.0.0.1/32"
    ROUTER_WEBFIG_SESSION_MINUTES: int = 120
    ROUTER_WEBFIG_PROXY_TIMEOUT_SECONDS: int = 20

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
