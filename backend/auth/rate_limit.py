"""
VENOM AI — auth/rate_limit.py
Redis-based sliding window rate limiter as a FastAPI Dependency.

Usage:
    from auth.rate_limit import rate_limit

    @router.post("/login")
    def login(
        req: LoginRequest,
        request: Request,
        db: Session = Depends(get_db),
        _rl: None = Depends(rate_limit(max_calls=5, period_seconds=60)),
    ):
        ...

How it works:
    - Each request gets a Redis key: "rl:<ip>:<path>"
    - The counter increments on every request
    - Redis auto-deletes the key after `period_seconds` (sliding window reset)
    - If the counter exceeds max_calls → HTTP 429 is raised
    - Falls back silently if Redis is unreachable (never blocks legitimate users
      due to infrastructure issues)
"""
from __future__ import annotations

import logging
import os

from fastapi import Depends, HTTPException, Request, status

logger = logging.getLogger("venom.rate_limit")

# ── Redis client (lazy singleton) ─────────────────────────────────────────
_redis_client = None

def _get_redis():
    global _redis_client
    if _redis_client is None:
        try:
            import redis as redis_lib
            _redis_client = redis_lib.from_url(
                os.getenv("REDIS_URL", "redis://redis:6379/0"),
                decode_responses=True,
                socket_connect_timeout=1,   # fail fast if Redis is down
                socket_timeout=1,
            )
            _redis_client.ping()            # confirm connection on first use
            logger.info("[RateLimit] Redis connection established")
        except Exception as e:
            logger.warning(f"[RateLimit] Redis unavailable — rate limiting disabled: {e}")
            _redis_client = None
    return _redis_client


def rate_limit(max_calls: int, period_seconds: int = 60):
    """
    Returns a FastAPI dependency that enforces IP-based rate limiting.

    Args:
        max_calls:       Maximum number of requests allowed in the window
        period_seconds:  Window size in seconds (counter resets after this)

    Example:
        Depends(rate_limit(5, 60))   → max 5 requests per 60 seconds per IP
    """
    def _dependency(request: Request) -> None:
        r = _get_redis()

        # If Redis is unavailable, skip rate limiting rather than
        # blocking all legitimate users due to infrastructure issues.
        if r is None:
            return

        # Build a key per IP + endpoint path
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "unknown")
        )
        key = f"rl:{client_ip}:{request.url.path}"

        try:
            # INCR is atomic — safe under concurrent requests
            # EXPIRE resets the TTL on every call (sliding window)
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.expire(key, period_seconds)
            results = pipe.execute()
            count = results[0]

            if count > max_calls:
                logger.warning(
                    f"[RateLimit] BLOCKED {client_ip} on {request.url.path} "
                    f"— {count}/{max_calls} in {period_seconds}s"
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "error":   "rate_limit_exceeded",
                        "message": (
                            f"Too many attempts. "
                            f"Maximum {max_calls} requests per {period_seconds} seconds. "
                            f"Please wait and try again."
                        ),
                    },
                    headers={"Retry-After": str(period_seconds)},
                )
        except HTTPException:
            raise          # re-raise our own 429
        except Exception as e:
            # Redis error mid-request — log and allow through
            logger.warning(f"[RateLimit] Redis error, allowing request: {e}")

    return _dependency
