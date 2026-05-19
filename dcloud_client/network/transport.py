"""Transport interfaces for future UDP, QUIC, WebRTC or libp2p backends."""

from __future__ import annotations

from typing import Protocol


class Transport(Protocol):
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def send_control(self, host: str, port: int, message: dict[str, object]) -> None: ...
