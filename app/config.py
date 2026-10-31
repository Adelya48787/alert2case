from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "postgresql://soc:soc@localhost:5432/alert2case"
    redis_url: str = "redis://localhost:6379/0"
    webhook_hmac_secret: str
    admin_token: str = ""
    vt_api_key: str = ""
    abuseipdb_api_key: str = ""
    otx_api_key: str = ""
    vt_base_url: str = "https://www.virustotal.com/api/v3"
    abuseipdb_base_url: str = "https://api.abuseipdb.com/api/v2"
    otx_base_url: str = "https://otx.alienvault.com/api/v1"
    case_backend: str = "file"  # file | thehive
    thehive_url: str = "http://localhost:9000"
    thehive_api_key: str = ""
    slack_webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    email_to: str = "soc-team@lab.local"
    auto_close_enabled: bool = False
    shadow_mode: bool = True
    dedup_window_s: int = 900


settings = Settings()
