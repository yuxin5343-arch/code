from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Dict, List

from communication.message_protocol import BaseMessage


class AsyncMessageQueue:
    """内存型异步消息总线，支持跨组件发布订阅。"""

    def __init__(self) -> None:
        self._queues: Dict[str, asyncio.Queue[BaseMessage]] = defaultdict(asyncio.Queue)

    async def publish(self, channel: str, message: BaseMessage) -> None:
        await self._queues[channel].put(message)

    async def consume(self, channel: str) -> BaseMessage:
        return await self._queues[channel].get()

    def get_channel_size(self, channel: str) -> int:
        return self._queues[channel].qsize()

    async def broadcast(self, channels: List[str], message: BaseMessage) -> None:
        """
        向多个通道广播消息。
        """
        for channel in channels:
            await self.publish(channel, message)
