"""Tiny exponential-backoff helper for transient AWS errors.

boto3 has built-in retries, but detectors want explicit, bounded backoff around
specific operations (S3 rule loads, DynamoDB writes) so a persistent failure
surfaces quickly rather than crashing mid-batch.
"""

import time
from collections.abc import Callable

from botocore.exceptions import ClientError

# Error codes worth retrying (throttling / transient service issues).
RETRYABLE_CODES: frozenset[str] = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "ThrottledException",
        "RequestLimitExceeded",
        "RequestThrottled",
        "TooManyRequestsException",
        "ProvisionedThroughputExceededException",
        "TransactionConflictException",
        "InternalError",
        "InternalServerError",
        "ServiceUnavailable",
        "SlowDown",
        "RequestTimeout",
    }
)


def with_backoff[T](
    fn: Callable[[], T],
    *,
    attempts: int = 3,
    base_delay: float = 0.2,
    retryable: frozenset[str] = RETRYABLE_CODES,
) -> T:
    """Call ``fn``, retrying retryable ClientErrors with exponential backoff.

    Re-raises immediately on non-retryable errors and after the final attempt.
    """
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in retryable or attempt == attempts - 1:
                raise
            time.sleep(base_delay * (2**attempt))
    raise RuntimeError("with_backoff: exhausted attempts without returning")  # unreachable
