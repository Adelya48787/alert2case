"""Ardıcıl xətalardan sonra provider sorğularını müvəqqəti dayandırır."""

import time


class CircuitBreaker:
    def __init__(
        self,
        name: str,
        fail_max: int = 5,
        reset_s: float = 60.0,
    ) -> None:
        self.name = name
        self.fail_max = fail_max
        self.reset_s = reset_s
        self.failures = 0
        self.opened_at: float | None = None

    @property
    def state(self) -> str:
        if self.opened_at is None:
            return "closed"
        if time.monotonic() - self.opened_at >= self.reset_s:
            return "half_open"
        return "open"

    def allow(self) -> bool:
        return self.state != "open"

    def success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def failure(self) -> None:
        self.failures += 1
        if self.state == "half_open" or self.failures >= self.fail_max:
            self.opened_at = time.monotonic()
