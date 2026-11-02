"""Log konfiqurasiyası: secret-lər heç vaxt loga düşmür."""

import logging

from app.config import settings

SECRET_FIELDS = (
    "vt_api_key",
    "abuseipdb_api_key",
    "otx_api_key",
    "thehive_api_key",
    "webhook_hmac_secret",
    "admin_token",
    "feedback_token",
    "slack_webhook_url",
    "telegram_bot_token",
)


class SecretMaskFilter(logging.Filter):
    def __init__(self) -> None:
        super().__init__()
        self.secrets = [v for f in SECRET_FIELDS if len(v := getattr(settings, f, "") or "") >= 8]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for s in self.secrets:
            if s in msg:
                msg = msg.replace(s, s[:4] + "***")
        record.msg, record.args = msg, None
        return True


def setup_logging(level: int = logging.INFO) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(SecretMaskFilter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    logging.getLogger("httpx").setLevel(logging.WARNING)  # httpx URL-ləri (açar ola bilər) loglamasın
