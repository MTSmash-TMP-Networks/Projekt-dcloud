"""Native dcloud browser window based on Qt WebEngine.

The dashboard itself runs in a normal web page. A web page can only embed other
pages through an iframe or a server-side proxy, and modern sites such as Google
intentionally block or heavily restrict that mode. This module is therefore a
small native browser process with Qt WebEngine. Normal Internet pages are loaded
directly by the engine; *.dcloud pages are redirected through the local dcloud
resolver endpoint.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib import parse as url_parse

try:  # pragma: no cover - only available in the desktop runtime
    from PySide6.QtCore import QUrl, Qt
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import (
        QApplication,
        QFileDialog,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QToolBar,
    )
    from PySide6.QtWebEngineCore import QWebEngineDownloadRequest, QWebEnginePage, QWebEngineProfile
    from PySide6.QtWebEngineWidgets import QWebEngineView
except Exception as exc:  # pragma: no cover - shown to CLI/user when missing
    print(
        "Der native dcloud Browser benötigt PySide6/Qt WebEngine. "
        "Bitte `pip install -r requirements.txt` ausführen.",
        file=sys.stderr,
    )
    print(str(exc), file=sys.stderr)
    raise SystemExit(2)


APP_TITLE = "dcloud Browser"


def _normalize_url(value: str | None, fallback: str) -> str:
    raw = (value or "").strip() or fallback
    if raw.startswith("//"):
        raw = "https:" + raw
    if "://" not in raw:
        raw = ("http://" if ".dcloud" in raw.lower() else "https://") + raw
    return raw


def _is_dcloud_url(url: QUrl) -> bool:
    return url.scheme().lower() in {"http", "https"} and url.host().lower().endswith(".dcloud")


def _proxy_url(app_url: str, target: str, browser_token: str = "") -> QUrl:
    encoded = url_parse.quote(target, safe="")
    token_part = f"&browser_token={url_parse.quote(browser_token, safe='')}" if browser_token else ""
    return QUrl(f"{app_url.rstrip('/')}/browser/view?native=1&url={encoded}{token_part}")


def _target_from_proxy_url(app_url: str, value: QUrl) -> str | None:
    parsed = url_parse.urlsplit(value.toString())
    app_parsed = url_parse.urlsplit(app_url.rstrip("/"))
    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.netloc != app_parsed.netloc or parsed.path != "/browser/view":
        return None
    query = url_parse.parse_qs(parsed.query)
    target = query.get("url", [""])[0]
    return target or None


class DcloudWebPage(QWebEnginePage):
    def __init__(self, app_url: str, browser_token: str, profile: QWebEngineProfile, parent: object | None = None) -> None:
        super().__init__(profile, parent)
        self.app_url = app_url.rstrip("/")
        self.browser_token = browser_token

    def acceptNavigationRequest(self, url: QUrl, nav_type: QWebEnginePage.NavigationType, is_main_frame: bool) -> bool:  # noqa: N802
        if is_main_frame and _is_dcloud_url(url):
            self.load(_proxy_url(self.app_url, url.toString(), self.browser_token))
            return False
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)


class BrowserWindow(QMainWindow):
    def __init__(self, *, app_url: str, initial_url: str, profile_dir: str | None = None, browser_token: str = "") -> None:
        super().__init__()
        self.app_url = app_url.rstrip("/")
        self.home_url = initial_url
        self.browser_token = browser_token
        self.setWindowTitle(APP_TITLE)
        self.resize(1220, 820)

        profile_path = Path(profile_dir).expanduser() if profile_dir else Path.home() / ".dcloud" / "browser_profile"
        profile_path.mkdir(parents=True, exist_ok=True)
        self.profile = QWebEngineProfile("dcloud-browser", self)
        self.profile.setPersistentStoragePath(str(profile_path))
        self.profile.setCachePath(str(profile_path / "cache"))
        self.profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 dcloud-browser/1.0"
        )
        self.profile.downloadRequested.connect(self._handle_download)

        self.view = QWebEngineView(self)
        self.page = DcloudWebPage(self.app_url, self.browser_token, self.profile, self)
        self.view.setPage(self.page)
        self.setCentralWidget(self.view)

        toolbar = QToolBar("Navigation", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        self.back_action = QAction("←", self)
        self.back_action.setToolTip("Zurück")
        self.back_action.triggered.connect(self.view.back)
        toolbar.addAction(self.back_action)

        self.forward_action = QAction("→", self)
        self.forward_action.setToolTip("Vor")
        self.forward_action.triggered.connect(self.view.forward)
        toolbar.addAction(self.forward_action)

        self.reload_action = QAction("↻", self)
        self.reload_action.setToolTip("Neu laden")
        self.reload_action.triggered.connect(self.view.reload)
        toolbar.addAction(self.reload_action)

        self.home_action = QAction("🏠", self)
        self.home_action.setToolTip("Startseite")
        self.home_action.triggered.connect(lambda: self.navigate(self.home_url))
        toolbar.addAction(self.home_action)

        self.url_input = QLineEdit(self)
        self.url_input.setClearButtonEnabled(True)
        self.url_input.setPlaceholderText("peername.dcloud oder https://google.com")
        self.url_input.returnPressed.connect(lambda: self.navigate(self.url_input.text()))
        toolbar.addWidget(self.url_input)

        self.open_action = QAction("Los", self)
        self.open_action.triggered.connect(lambda: self.navigate(self.url_input.text()))
        toolbar.addAction(self.open_action)

        self.view.urlChanged.connect(self._sync_url_bar)
        self.view.titleChanged.connect(self._sync_title)
        self.view.loadFinished.connect(self._on_load_finished)

        self.navigate(initial_url)

    def navigate(self, value: str | None) -> None:
        url_text = _normalize_url(value, self.home_url)
        self.url_input.setText(url_text)
        qurl = QUrl(url_text)
        if _is_dcloud_url(qurl):
            self.view.load(_proxy_url(self.app_url, url_text, self.browser_token))
        else:
            self.view.load(qurl)

    def _display_url(self, url: QUrl) -> str:
        proxied_target = _target_from_proxy_url(self.app_url, url)
        return proxied_target or url.toString()

    def _sync_url_bar(self, url: QUrl) -> None:
        self.url_input.setText(self._display_url(url))

    def _sync_title(self, title: str) -> None:
        clean_title = title.strip() or APP_TITLE
        self.setWindowTitle(f"{clean_title} - {APP_TITLE}")

    def _on_load_finished(self, ok: bool) -> None:
        if not ok:
            self.statusBar().showMessage("Seite konnte nicht vollständig geladen werden", 5000)
        else:
            self.statusBar().showMessage("Bereit", 1600)

    def _handle_download(self, download: QWebEngineDownloadRequest) -> None:
        suggested = download.suggestedFileName() or "download"
        target, _ = QFileDialog.getSaveFileName(self, "Download speichern", suggested)
        if not target:
            download.cancel()
            return
        target_path = Path(target)
        download.setDownloadDirectory(str(target_path.parent))
        download.setDownloadFileName(target_path.name)
        download.accept()
        self.statusBar().showMessage(f"Download gestartet: {target_path.name}", 5000)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Native dcloud WebEngine browser")
    parser.add_argument("--app-url", required=True, help="Local dcloud dashboard base URL, e.g. http://127.0.0.1:5000")
    parser.add_argument("--url", default="", help="Initial URL")
    parser.add_argument("--profile-dir", default="", help="Persistent browser profile/cache directory")
    parser.add_argument("--browser-token", default="", help="Ephemeral local access token for dcloud browser proxy")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
        os.environ.setdefault("QTWEBENGINE_DISABLE_SANDBOX", "1")
    app = QApplication(sys.argv)
    initial_url = _normalize_url(args.url, args.app_url)
    window = BrowserWindow(app_url=args.app_url, initial_url=initial_url, profile_dir=args.profile_dir or None, browser_token=args.browser_token or "")
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
