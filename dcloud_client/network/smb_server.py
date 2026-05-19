"""Optional embedded SMB server for direct filesystem access."""

from __future__ import annotations

import logging
from pathlib import Path
import errno

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
        self.running = False
        self.actual_port = self.port
        self.last_error = ""

    def start(self) -> None:
        try:
            from impacket import smbserver
        except Exception as exc:  # pragma: no cover - depends on optional dependency
            self.running = False
            self.last_error = "impacket ist nicht installiert. Bitte 'pip install impacket' ausführen."
            raise RuntimeError(self.last_error) from exc

        self.root.mkdir(parents=True, exist_ok=True)
        listen_port = self.port
        for candidate in [self.port, 1445] if self.port == 445 else [self.port]:
            try:
                server = smbserver.SimpleSMBServer(listenAddress=self.host, listenPort=candidate)
                listen_port = candidate
                break
            except OSError as exc:
                if exc.errno == errno.EACCES and candidate == 445:
                    LOG.warning("SMB-Port 445 benötigt Root-Rechte; weiche auf Port 1445 aus")
                    continue
                self.running = False
                self.last_error = str(exc)
                raise
        server.addShare(self.share_name, str(self.root), comment="dcloud storage")
        if self.username:
            server.addCredential(self.username, 0, "", self.password)
        try:
            server.setSMB2Support(True)
        except Exception:
            pass
        self._server = server
        self.actual_port = listen_port
        self.running = True
        self.last_error = ""
        LOG.info("Embedded SMB server started on smb://%s:%s/%s", self.host, listen_port, self.share_name)
        try:
            server.start()
        except Exception as exc:
            self.running = False
            self.last_error = str(exc)
            raise

    def stop(self) -> None:
        if self._server is None:
            return
        try:
            self._server.stop()
        finally:
            self.running = False
            self._server = None
