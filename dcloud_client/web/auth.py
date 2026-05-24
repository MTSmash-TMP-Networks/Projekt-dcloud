"""Local user management and dashboard authentication helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import json
import os
import re
import tempfile
import threading

from werkzeug.security import check_password_hash, generate_password_hash


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


@dataclass
class DcloudUser:
    username: str
    password_hash: str
    role: str = "user"
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""
    last_login_at: str = ""

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "role": self.role,
            "enabled": bool(self.enabled),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_login_at": self.last_login_at,
        }


class UserStore:
    """Small atomic JSON user database for the local dashboard."""

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._users: dict[str, DcloudUser] = {}
        self.load()

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def normalize_username(username: str) -> str:
        username = (username or "").strip()
        if not _USERNAME_RE.match(username):
            raise ValueError("Benutzername muss 3-32 Zeichen haben und darf nur Buchstaben, Zahlen, Punkt, Minus und Unterstrich enthalten")
        return username

    @staticmethod
    def normalize_role(role: str) -> str:
        role = (role or "user").strip().lower()
        if role not in {"admin", "user"}:
            raise ValueError("Rolle muss admin oder user sein")
        return role

    @staticmethod
    def validate_password(password: str) -> str:
        password = password or ""
        if len(password) < 8:
            raise ValueError("Passwort muss mindestens 8 Zeichen lang sein")
        return password

    def load(self) -> None:
        with self._lock:
            self._users = {}
            if not self.path.exists():
                return
            try:
                with self.path.open("r", encoding="utf-8") as handle:
                    raw = json.load(handle) or {}
            except Exception:
                raw = {}
            items = raw.get("users", raw if isinstance(raw, dict) else {})
            if not isinstance(items, dict):
                return
            for username, payload in items.items():
                if not isinstance(payload, dict):
                    continue
                try:
                    clean_username = self.normalize_username(str(username))
                except ValueError:
                    continue
                password_hash = str(payload.get("password_hash") or "")
                if not password_hash:
                    continue
                self._users[clean_username] = DcloudUser(
                    username=clean_username,
                    password_hash=password_hash,
                    role=self.normalize_role(str(payload.get("role") or "user")),
                    enabled=bool(payload.get("enabled", True)),
                    created_at=str(payload.get("created_at") or ""),
                    updated_at=str(payload.get("updated_at") or ""),
                    last_login_at=str(payload.get("last_login_at") or ""),
                )

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "version": 1,
                "users": {
                    username: {
                        "password_hash": user.password_hash,
                        "role": user.role,
                        "enabled": bool(user.enabled),
                        "created_at": user.created_at,
                        "updated_at": user.updated_at,
                        "last_login_at": user.last_login_at,
                    }
                    for username, user in sorted(self._users.items())
                },
            }
            fd, tmp_name = tempfile.mkstemp(prefix="users-", suffix=".tmp", dir=self.path.parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
                    handle.flush()
                Path(tmp_name).replace(self.path)
                try:
                    self.path.chmod(0o600)
                except OSError:
                    pass
            except Exception:
                Path(tmp_name).unlink(missing_ok=True)
                raise

    def has_users(self) -> bool:
        with self._lock:
            return bool(self._users)

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            return [user.to_public_dict() for _, user in sorted(self._users.items())]

    def get(self, username: str) -> DcloudUser | None:
        with self._lock:
            return self._users.get(username)

    def verify(self, username: str, password: str) -> DcloudUser | None:
        username = (username or "").strip()
        with self._lock:
            user = self._users.get(username)
            if user is None or not user.enabled:
                return None
            if not check_password_hash(user.password_hash, password or ""):
                return None
            user.last_login_at = self.now()
            user.updated_at = user.updated_at or user.last_login_at
            self.save()
            return user

    def create_user(self, username: str, password: str, *, role: str = "user", enabled: bool = True) -> DcloudUser:
        username = self.normalize_username(username)
        role = self.normalize_role(role)
        password = self.validate_password(password)
        now = self.now()
        with self._lock:
            if username in self._users:
                raise ValueError("Benutzer existiert bereits")
            self._users[username] = DcloudUser(
                username=username,
                password_hash=generate_password_hash(password),
                role=role,
                enabled=bool(enabled),
                created_at=now,
                updated_at=now,
            )
            self.save()
            return self._users[username]

    def update_user(
        self,
        username: str,
        *,
        role: str | None = None,
        enabled: bool | None = None,
        password: str | None = None,
    ) -> DcloudUser:
        username = self.normalize_username(username)
        with self._lock:
            user = self._users.get(username)
            if user is None:
                raise ValueError("Benutzer wurde nicht gefunden")
            if role is not None:
                user.role = self.normalize_role(role)
            if enabled is not None:
                user.enabled = bool(enabled)
            if password:
                user.password_hash = generate_password_hash(self.validate_password(password))
            user.updated_at = self.now()
            self.save()
            return user

    def delete_user(self, username: str) -> None:
        username = self.normalize_username(username)
        with self._lock:
            if username not in self._users:
                raise ValueError("Benutzer wurde nicht gefunden")
            if len(self._users) <= 1:
                raise ValueError("Der letzte Benutzer kann nicht gelöscht werden")
            del self._users[username]
            self.save()

    def count_admins(self, *, enabled_only: bool = True, exclude_username: str | None = None) -> int:
        with self._lock:
            return sum(
                1
                for username, user in self._users.items()
                if user.role == "admin"
                and (not enabled_only or user.enabled)
                and username != exclude_username
            )
