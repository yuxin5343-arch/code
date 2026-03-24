from __future__ import annotations

from typing import Any, Dict

import httpx


class AsyncAPIClient:
    """用于跨进程/跨设备通信的异步 HTTP 客户端。"""

    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    async def post_json(self, url: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            return resp.json()

    async def get_json(self, url: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
