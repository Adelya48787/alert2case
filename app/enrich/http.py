"""Bütün xarici sorğular üçün ortaq HTTP client: timeout, retry, xəta növləri."""

import logging
import httpx
from tenacity import (
    AsyncRetrying,
    RetryCallState,
    retry_if_exception_type,
    stop_after_attempt,
    wait_random_exponential,
)

log = logging.getLogger("enrich.http")


class ProviderError(Exception):
    """Provider-in cavabı ilə bağlı xəta."""


class AuthError(ProviderError):
    """401/403: açar səhvdir və ya ləğv olunub. Retry mənasızdır."""


class ServerError(ProviderError):
    """5xx: provider-in daxili xətası. Müvəqqətidir."""


class RateLimited(ProviderError):
    """429: limit aşılıb."""

    def __init__(self, retry_after: float | None) -> None:
        super().__init__(f"429, Retry-After={retry_after}")
        self.retry_after = retry_after


TIMEOUT = httpx.Timeout(8.0, connect=3.0)
ATTEMPTS = 3
_backoff = wait_random_exponential(multiplier=1, max=8)  # 0–1 s, 0–2 s, 0–4 s ...
_client: httpx.AsyncClient | None = None


def client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=TIMEOUT, headers={"User-Agent": "alert2case/1.0"})
    return _client


def _wait(state: RetryCallState) -> float:
    exc = state.outcome.exception() if state.outcome else None
    if isinstance(exc, RateLimited) and exc.retry_after is not None:
        return min(exc.retry_after, 30.0)  # provider-in dediyi qədər, max 30 s
    return _backoff(state)


def _retrying() -> AsyncRetrying:
    return AsyncRetrying(
        retry=retry_if_exception_type((httpx.TransportError, ServerError, RateLimited)),
        stop=stop_after_attempt(ATTEMPTS),
        wait=_wait,
        reraise=True,
    )


async def get_json(provider: str, url: str, headers: dict, params: dict | None = None) -> dict | None:
    """200 → dict, 404 → None. Qalan hallarda xəta atır (retry-dan sonra)."""
    async for attempt in _retrying():
        with attempt:
            r = await client().get(url, headers=headers, params=params)
            if r.status_code == 200:
                return r.json()
            log.warning(
                "provider=%s HTTP %s cəhd=%s", provider, r.status_code, attempt.retry_state.attempt_number
            )
            if r.status_code == 404:
                return None
            if r.status_code in (401, 403):
                raise AuthError(f"{provider}: HTTP {r.status_code}")
            if r.status_code == 429:
                ra = r.headers.get("Retry-After", "")
                raise RateLimited(float(ra) if ra.replace(".", "", 1).isdigit() else None)
            if r.status_code >= 500:
                raise ServerError(f"{provider}: HTTP {r.status_code}")
            raise ProviderError(f"{provider}: gözlənilməz HTTP {r.status_code}")
    return None  # pragma: no cover
