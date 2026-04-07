from pydantic_settings import BaseSettings
from dotenv import load_dotenv


load_dotenv()  # Optional if you use a .env file

class Settings(BaseSettings):
    # PostgreSQL connection - set via environment variable
    DATABASE_URL: str = "postgresql+asyncpg://isp_user:isp_secure_pass_2024@localhost:5434/isp_billing_db"
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    # MikroTik Configuration (via WireGuard VPN)
    MIKROTIK_HOST: str = "10.0.0.2"  # MikroTik IP over WireGuard VPN
    MIKROTIK_PORT: int = 8728
    MIKROTIK_USERNAME: str = "admin"
    MIKROTIK_PASSWORD: str = "mvnm"  # Set in .env file
    PPPOE_RATE_LIMIT_HEADROOM: float = 1.08
    
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
    MPESA_B2B_MIN_PAYOUT: float = 100.0
    MPESA_B2B_DAILY_PAYOUT_ENABLED: bool = False

    # Router Auto-Provisioning
    SERVER_PUBLIC_IP: str = ""
    WG_MANAGER_URL: str = "http://host.docker.internal:8729"
    WG_MANAGER_SECRET: str = "change-me-wg-secret"
    PROVISION_BASE_URL: str = "https://isp.bitwavetechnologies.net"
    L2TP_IPSEC_PSK: str = "BitwaveL2TP2026!Secure"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
