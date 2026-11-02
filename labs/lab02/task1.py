"""Завдання 1. Модель користувача, сесії та аудиту (ООП)."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

PBKDF2_ITERATIONS = 200_000
SESSION_TIMEOUT_SEC = 900

_EMAIL_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


class User:
    """Користувач системи з безпечним зберіганням пароля."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "user",
        active: bool = True,
    ):
        self.username = username
        self.email = email  # через @property
        self.role = role
        self.active = active
        self.__password_hash: bytes | None = None
        self.__password_salt: bytes | None = None

    @property
    def email(self) -> str:
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str):
            raise ValueError(f"Некоректний email: {value!r}")

        # Спрощена перевірка: є @, є крапка після @, немає пробілів
        parts = value.split("@")
        if len(parts) != 2 or "." not in parts[1] or " " in value:
            raise ValueError(f"Некоректний email: {value!r}")

        self._email = value

    def set_password(self, password: str) -> None:
        if not password:
            raise ValueError("Пароль не може бути порожнім")
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )
        self.__password_salt = salt
        self.__password_hash = digest

    def check_password(self, password: str) -> bool:
        if self.__password_hash is None or self.__password_salt is None:
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self.__password_salt,
            PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(digest, self.__password_hash)

    def deactivate(self) -> None:
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return f"User(username={self.username}, email={self.email}, role={self.role}, {state})"


class Admin(User):
    """Адміністратор із набором дозволів."""

    def __init__(
        self,
        username: str,
        email: str,
        role: str = "admin",
        active: bool = True,
        permissions: list[str] | None = None,
    ):
        super().__init__(username, email, role, active)
        self.permissions: set[str] = set(permissions) if permissions else set()

    def grant_permission(self, permission: str) -> None:
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    def __str__(self) -> str:
        base = super().__str__()
        perms = ", ".join(sorted(self.permissions)) or "—"
        return f"{base[:-1]}, permissions=[{perms}])"


class Session:
    """Сеанс користувача з IP-адресою та часом активності (UTC)."""

    def __init__(self, ip: str, login_time: datetime | None = None):
        now = login_time or datetime.now(UTC)
        self.ip = ip
        self.login_time = now
        self.last_activity = now

    def touch(self) -> None:
        self.last_activity = datetime.now(UTC)

    def is_active(self, timeout_sec: int = SESSION_TIMEOUT_SEC) -> bool:
        if timeout_sec <= 0:
            raise ValueError("timeout_sec має бути додатним")
        delta = datetime.now(UTC) - self.last_activity
        return delta < timedelta(seconds=timeout_sec)


@dataclass
class AuditRecord:
    timestamp: datetime
    username: str
    action: str


class AuditLog:
    """Журнал аудиторії у пам'яті."""

    def __init__(self) -> None:
        self.records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        self.records.append(
            AuditRecord(
                timestamp=datetime.now(UTC),
                username=username,
                action=action,
            )
        )

    def show_all(self) -> list[AuditRecord]:
        return list(self.records)


class UserAccount:
    """Композиція User + Session + AuditLog з доступом за ключем."""

    _ALLOWED_KEYS = {"user", "session", "audit_log"}

    def __init__(
        self,
        user: User,
        session: Session | None = None,
        audit_log: AuditLog | None = None,
    ):
        self._user = user
        self._session: Session | None = session
        self._audit_log = audit_log or AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        if not self._user.active:
            self._audit_log.add_log(username, "login_failure")
            return False
        if username != self._user.username or not self._user.check_password(
            password
        ):
            self._audit_log.add_log(username, "login_failure")
            return False
        self._session = Session(ip=ip)
        self._session.touch()
        self._audit_log.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        if self._session is None:
            return False
        return self._session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        if self._session is not None:
            self._audit_log.add_log(self._user.username, "logout")
        self._session = None

    def __getitem__(self, key: str):
        if key not in self._ALLOWED_KEYS:
            raise KeyError(f"Невідомий ключ: {key}")
        return {
            "user": self._user,
            "session": self._session,
            "audit_log": self._audit_log,
        }[key]

    def __setitem__(self, key: str, value) -> None:
        if key == "user":
            if not isinstance(value, User):
                raise TypeError("Очікується об'єкт User")
            self._user = value
        elif key == "session":
            if value is not None and not isinstance(value, Session):
                raise TypeError("Очікується об'єкт Session або None")
            self._session = value
        elif key == "audit_log":
            if not isinstance(value, AuditLog):
                raise TypeError("Очікується об'єкт AuditLog")
            self._audit_log = value
        else:
            raise KeyError(f"Невідомий ключ: {key}")
