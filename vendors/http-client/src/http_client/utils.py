from datetime import datetime
from typing import Optional

from fake_useragent import UserAgent
from loguru import logger
from tenacity import RetryCallState
from tenacity.wait import wait_base

from .errors import RateLimitError

logger.add("test.log", serialize=True, format="[{file.name}] {message}")


class wait_for_retry_after_header(wait_base):
    def __init__(self, fallback):
        self.fallback = fallback

    def __call__(self, retry_state: RetryCallState) -> float:
        if retry_state.outcome.failed:
            exception = retry_state.outcome.exception()
            if isinstance(exception, RateLimitError):
                retry_after = exception.response.headers.get("Retry-After")
                if retry_after:
                    to_retry = parse_retry_after(retry_after)
                    logger.info(f"Rate limited. Retrying after {to_retry} seconds")
                    return to_retry

        return self.fallback(retry_state)


def parse_retry_after(retry_after) -> Optional[float]:
    try:
        return float(retry_after)
    except ValueError:
        try:
            retry_date = datetime.strptime(retry_after, "%a, %d %b %Y %H:%M:%S %Z")
            return max(0.0, (retry_date - datetime.now()).total_seconds())
        except (ValueError, TypeError):
            return None


def log_attempt_number(retry_state: RetryCallState):
    if retry_state.outcome.failed:
        exception = retry_state.outcome.exception() or retry_state.outcome._exception
        logger.warning(
            f"Retry attempt #{retry_state.attempt_number} failed: {exception}"
        )


def get_user_agent():
    return UserAgent().random
