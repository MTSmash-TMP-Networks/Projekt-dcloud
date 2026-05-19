"""Optional embedded SMB server for direct filesystem access."""

from __future__ import annotations

import logging
from pathlib import Path

LOG = logging.getLogger(__name__)


class EmbeddedSmbServer:
    def __init__(self, *, root: Path, host: str, port: int, share_name: str, username: str = "", password: str = "") -> None:
        self.root = Path(root)
        self.host = host
        self.port = int(port)
        self.share_name = share_name
        self.username = username
        self.password = password
        self._server = None

    def start(self) -> None:
        try:
            from impacket import smbserver
        except Exception as exc:  # pragma: no cover - depends on optional dependency
            raise RuntimeError("impacket ist nicht installiert. Bitte 'pip install impacket' ausführen.") from exc

        self.root.mkdir(parents=True, exist_ok=True)
        server = smbserver.SimpleSMBServer(listenAddress=self.host, listenPort=self.port)
        server.addShare(self.share_name, str(self.root), comment="dcloud storage")
        if self.username:
            server.addCredential(self.username, 0, "", self.password)

        # Keep modern SMB support enabled where available.
        try:
            server.setSMB2Support(True)
        except Exception:
            pass

        self._server = server
        LOG.info("Embedded SMB server started on smb://%s:%s/%s", self.host, self.port, self.share_name)
        server.start()

    def stop(self) -> None:
        if self._server is None:
            return
        try:
            self._server.stop()
        finally:
            self._server = None
