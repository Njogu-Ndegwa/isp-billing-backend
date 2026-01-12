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
    
    # M-Pesa Configuration
    MPESA_CONSUMER_KEY: str
    MPESA_CONSUMER_SECRET: str
    MPESA_SHORTCODE: str
    MPESA_PASSKEY: str
    MPESA_CALLBACK_URL: str
    MPESA_ENVIRONMENT: str

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"

settings = Settings()
