import os
import time
import httpx
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import jwt

CLERK_JWKS_URL = "https://api.clerk.com/v1/jwks"
JWKS_CACHE_TTL_SECONDS = 3600

_bearer = HTTPBearer()
_jwks_cache: dict | None = None
_jwks_cached_at: float = 0.0


def _get_jwks(force: bool = False) -> dict:
    global _jwks_cache, _jwks_cached_at
    stale = (time.time() - _jwks_cached_at) > JWKS_CACHE_TTL_SECONDS
    if _jwks_cache is None or force or stale:
        resp = httpx.get(CLERK_JWKS_URL, headers={"Authorization": f"Bearer {os.environ['CLERK_SECRET_KEY']}"})
        resp.raise_for_status()
        _jwks_cache = resp.json()
        _jwks_cached_at = time.time()
    return _jwks_cache


def _find_key(kid: str) -> dict | None:
    jwks = _get_jwks()
    key = next((k for k in jwks["keys"] if k["kid"] == kid), None)
    if key is None:
        # Key may have just rotated on Clerk's side — refetch once before giving up.
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
        issuer = os.environ.get("CLERK_ISSUER")
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False, "verify_iss": issuer is not None},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
