import os
import threading
import time
import httpx
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

CLERK_JWKS_URL = "https://api.clerk.com/v1/jwks"
JWKS_CACHE_TTL_SECONDS = 3600
_JWKS_HTTP_TIMEOUT = 5.0
# An unauthenticated caller can pick the `kid` in a token header, and an unknown
# kid triggers a forced JWKS refetch. Rate-limit those so a stream of bogus
# tokens can't hammer Clerk / exhaust the FastAPI threadpool.
_JWKS_FORCE_MIN_INTERVAL = 60.0

_bearer = HTTPBearer()
_jwks_lock = threading.Lock()
_jwks_cache: dict | None = None
_jwks_cached_at: float = 0.0
_jwks_forced_at: float = 0.0

_ISSUER = os.environ.get("CLERK_ISSUER")
if not _ISSUER:
    print("[auth] WARNING: CLERK_ISSUER not set — JWT 'iss' claim will not be verified", flush=True)


def _get_jwks(force: bool = False) -> dict:
    global _jwks_cache, _jwks_cached_at, _jwks_forced_at
    with _jwks_lock:
        now = time.time()
        stale = (now - _jwks_cached_at) > JWKS_CACHE_TTL_SECONDS
        if force:
            if (now - _jwks_forced_at) < _JWKS_FORCE_MIN_INTERVAL:
                force = False           # too soon since the last forced refetch
            else:
                _jwks_forced_at = now
        if _jwks_cache is None or force or stale:
            resp = httpx.get(
                CLERK_JWKS_URL,
                headers={"Authorization": f"Bearer {os.environ['CLERK_SECRET_KEY']}"},
                timeout=_JWKS_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            _jwks_cache = resp.json()
            _jwks_cached_at = time.time()
        return _jwks_cache


def _find_key(kid: str) -> dict | None:
    jwks = _get_jwks()
    key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if key is None:
        # Key may have just rotated on Clerk's side — refetch once before giving
        # up (the refetch is rate-limited inside _get_jwks).
        jwks = _get_jwks(force=True)
        key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    return key


def get_current_user(credentials: HTTPAuthorizationCredentials = Security(_bearer)) -> dict:
    """
    FastAPI dependency. Validates the Clerk JWT and returns the decoded payload.
    Use as: user = Depends(get_current_user)
    """
    token = credentials.credentials
    try:
        header = jwt.get_unverified_header(token)
        key = _find_key(header["kid"])
        if key is None:
            raise HTTPException(status_code=401, detail="Unknown signing key")

        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=_ISSUER,
            options={"verify_aud": False, "verify_iss": _ISSUER is not None},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
