"""
Async HTTP client for fuzzing IDOR endpoints.
"""
import asyncio
from typing import Dict, Optional, Tuple

import httpx


async def fetch_url(
    client: httpx.AsyncClient,
    url: str,
    headers: Optional[Dict[str, str]] = None,
) -> Tuple[Optional[int], Optional[bytes], Optional[str]]:
    """
    Fetch a URL and return (status, body, error).
    """
    client_headers = headers.copy() if headers else None
    try:
        response = await client.get(url, headers=client_headers)
        return response.status_code, response.content, None
    except Exception as exc:
        return None, None, str(exc)
