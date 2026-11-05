"""Core of the educational information system "ThermoControl".

The module is deliberately independent of a particular messenger.  A transport
adapter only has to pass a channel identifier and a command to ThermoControl.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import math
import os
from pathlib import Path
import secrets
import sqlite3
import struct
from typing import Iterable

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MIN_TEMPERATURE_C = -40.0
MAX_TEMPERATURE_C = 85.0
SAMPLE_PERIOD_S = 1
QUANTIZATION_STEP_C = 0.1
BUFFER_CAPACITY = 300
AVERAGE_WINDOW = 5
PBKDF2_ITERATIONS = 600_000
SESSION_TTL_HOURS = 24
LOCK_AFTER_FAILURES = 5
LOCK_MINUTES = 5


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_text(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class ProcessedSample:
    measured_at_utc: datetime
    raw_c: float
    filtered_c: float
    buffer_size: int


@dataclass(frozen=True)
class AlertEvent:
    user_id: int
    sensor_id: int
    value_c: float
    lower_c: float
    upper_c: float


class TemperatureSource:
    """Deterministic virtual temperature sensor from Laboratory work 1."""

    @staticmethod
    def value_at(t_seconds: float) -> float:
        value = (
            22.0
            + 2.0 * math.sin(2.0 * math.pi * t_seconds / 120.0)
            + 0.3 * math.sin(2.0 * math.pi * t_seconds / 10.0)
        )
        return round(value / QUANTIZATION_STEP_C) * QUANTIZATION_STEP_C


class SignalProcessor:
    """Validates samples, stores a 300-item buffer and averages the last five."""

    def __init__(
        self,
        capacity: int = BUFFER_CAPACITY,
        average_window: int = AVERAGE_WINDOW,
    ) -> None:
        if capacity < 1 or average_window < 1 or average_window > capacity:
            raise ValueError("Invalid buffer settings")
        self._samples: deque[float] = deque(maxlen=capacity)
        self.average_window = average_window

    @property
    def buffer_size(self) -> int:
        return len(self._samples)

    def accept(self, value_c: float, measured_at_utc: datetime) -> ProcessedSample | None:
        if not isinstance(value_c, (int, float)):
            return None
        value = float(value_c)
        if not math.isfinite(value):
            return None
        if not MIN_TEMPERATURE_C <= value <= MAX_TEMPERATURE_C:
            return None

        self._samples.append(value)
        window = list(self._samples)[-self.average_window :]
        filtered = sum(window) / len(window)
        return ProcessedSample(
            measured_at_utc=measured_at_utc,
            raw_c=value,
            filtered_c=round(filtered, 2),
            buffer_size=len(self._samples),
        )


class PasswordHasher:
    """PBKDF2-HMAC-SHA-256 password hashing with a unique random salt."""

    def __init__(self, iterations: int = PBKDF2_ITERATIONS) -> None:
        if iterations < 1:
            raise ValueError("Iteration count must be positive")
        self.iterations = iterations

    def create(self, password: str) -> tuple[bytes, bytes, int]:
        if len(password) < 8:
            raise ValueError("Password must contain at least 8 characters")
        salt = secrets.token_bytes(16)
        digest = self._derive(password, salt, self.iterations)
        return salt, digest, self.iterations

    def verify(self, password: str, salt: bytes, expected: bytes, iterations: int) -> bool:
        actual = self._derive(password, salt, iterations)
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def _derive(password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations, dklen=32
        )


class MeasurementCipher:
    """Authenticated encryption for stored measurements; not user authentication."""

    def __init__(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError("AES key must contain 16, 24 or 32 bytes")
        self._aes = AESGCM(key)

    def encrypt(self, sensor_id: int, measured_at_utc: str, value_c: float) -> bytes:
        nonce = secrets.token_bytes(12)
        associated_data = f"{sensor_id}|{measured_at_utc}".encode("utf-8")
        plaintext = struct.pack("!d", value_c)
        return nonce + self._aes.encrypt(nonce, plaintext, associated_data)

    def decrypt(self, sensor_id: int, measured_at_utc: str, payload: bytes) -> float:
        if len(payload) < 13:
            raise ValueError("Encrypted measurement is damaged")
        nonce, ciphertext = payload[:12], payload[12:]
        associated_data = f"{sensor_id}|{measured_at_utc}".encode("utf-8")
        plaintext = self._aes.decrypt(nonce, ciphertext, associated_data)
        return struct.unpack("!d", plaintext)[0]


def load_or_create_key(path: str | Path) -> bytes:
    """Loads a local key or creates it outside the database on first launch."""

    key_path = Path(path)
    if key_path.exists():
        return key_path.read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(key_path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(key)
    return key


class Repository:
    def __init__(
        self,
        db_path: str | Path,
        cipher: MeasurementCipher,
        password_hasher: PasswordHasher | None = None,
    ) -> None:
        self.db_path = str(db_path)
        self.cipher = cipher
        self.password_hasher = password_hasher or PasswordHasher()
        self.connection = sqlite3.connect(self.db_path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS User (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL UNIQUE,
                password_salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                password_iterations INTEGER NOT NULL,
                timezone TEXT NOT NULL DEFAULT 'Europe/Moscow',
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until_utc TEXT
            );

            CREATE TABLE IF NOT EXISTS AuthSession (
                session_id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES User(user_id),
                channel_user_id TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                revoked_at_utc TEXT
            );

            CREATE UNIQUE INDEX IF NOT EXISTS uq_active_channel_session
            ON AuthSession(channel_user_id)
            WHERE revoked_at_utc IS NULL;

            CREATE TABLE IF NOT EXISTS Sensor (
                sensor_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                period_s INTEGER NOT NULL DEFAULT 1 CHECK (period_s > 0)
            );

            CREATE TABLE IF NOT EXISTS Subscription (
                user_id INTEGER NOT NULL REFERENCES User(user_id),
                sensor_id INTEGER NOT NULL REFERENCES Sensor(sensor_id),
                lower_c REAL NOT NULL,
                upper_c REAL NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                PRIMARY KEY (user_id, sensor_id),
                CHECK (-40 <= lower_c AND lower_c < upper_c AND upper_c <= 85)
            );

            CREATE TABLE IF NOT EXISTS Measurement (
                measurement_id INTEGER PRIMARY KEY AUTOINCREMENT,
                sensor_id INTEGER NOT NULL REFERENCES Sensor(sensor_id),
                measured_at_utc TEXT NOT NULL,
                value_enc BLOB NOT NULL,
                UNIQUE (sensor_id, measured_at_utc)
            );
            """
        )
        self.connection.execute(
            "INSERT OR IGNORE INTO Sensor(sensor_id, name, period_s) VALUES(1, ?, ?)",
            ("Виртуальный датчик помещения", SAMPLE_PERIOD_S),
        )
        self.connection.commit()

    def provision_user(
        self,
        login: str,
        password: str,
        sensor_id: int = 1,
        lower_c: float = 18.0,
        upper_c: float = 26.0,
    ) -> int:
        salt, digest, iterations = self.password_hasher.create(password)
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO User(login, password_salt, password_hash, password_iterations)
                VALUES(?, ?, ?, ?)
                """,
                (login, salt, digest, iterations),
            )
            user_id = int(cursor.lastrowid)
            self.connection.execute(
                """
                INSERT INTO Subscription(user_id, sensor_id, lower_c, upper_c, enabled)
                VALUES(?, ?, ?, ?, 1)
                """,
                (user_id, sensor_id, lower_c, upper_c),
            )
        return user_id

    def user_exists(self, login: str) -> bool:
        row = self.connection.execute(
            "SELECT 1 FROM User WHERE login = ? LIMIT 1", (login,)
        ).fetchone()
        return row is not None

    def authenticate(
        self,
        login: str,
        password: str,
        channel_user_id: str,
        now: datetime | None = None,
    ) -> str | None:
        moment = now or utc_now()
        row = self.connection.execute(
            "SELECT * FROM User WHERE login = ?", (login,)
        ).fetchone()

        if row is None:
            # A dummy calculation reduces the timing difference for an unknown login.
            self.password_hasher.verify(
                password,
                b"\x00" * 16,
                b"\x00" * 32,
                self.password_hasher.iterations,
            )
            return None

        locked_until = row["locked_until_utc"]
        if locked_until and parse_utc(locked_until) > moment:
            return None
        if not row["active"]:
            return None

        valid = self.password_hasher.verify(
            password,
            row["password_salt"],
            row["password_hash"],
            row["password_iterations"],
        )
        if not valid:
            attempts = int(row["failed_attempts"]) + 1
            lock_value: str | None = None
            if attempts >= LOCK_AFTER_FAILURES:
                attempts = 0
                lock_value = utc_text(moment + timedelta(minutes=LOCK_MINUTES))
            with self.connection:
                self.connection.execute(
                    """
                    UPDATE User SET failed_attempts = ?, locked_until_utc = ?
                    WHERE user_id = ?
                    """,
                    (attempts, lock_value, row["user_id"]),
                )
            return None

        session_id = secrets.token_urlsafe(32)
        created = utc_text(moment)
        expires = utc_text(moment + timedelta(hours=SESSION_TTL_HOURS))
        with self.connection:
            self.connection.execute(
                """
                UPDATE AuthSession SET revoked_at_utc = ?
                WHERE channel_user_id = ? AND revoked_at_utc IS NULL
                """,
                (created, channel_user_id),
            )
            self.connection.execute(
                """
                INSERT INTO AuthSession(
                    session_id, user_id, channel_user_id, created_at_utc, expires_at_utc
                ) VALUES(?, ?, ?, ?, ?)
                """,
                (session_id, row["user_id"], channel_user_id, created, expires),
            )
            self.connection.execute(
                """
                UPDATE User SET failed_attempts = 0, locked_until_utc = NULL
                WHERE user_id = ?
                """,
                (row["user_id"],),
            )
        return session_id

    def logout(self, channel_user_id: str, now: datetime | None = None) -> bool:
        moment = utc_text(now or utc_now())
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE AuthSession SET revoked_at_utc = ?
                WHERE channel_user_id = ? AND revoked_at_utc IS NULL
                """,
                (moment, channel_user_id),
            )
        return cursor.rowcount > 0

    def authenticated_user(
        self, channel_user_id: str, now: datetime | None = None
    ) -> sqlite3.Row | None:
        moment = utc_text(now or utc_now())
        return self.connection.execute(
            """
            SELECT U.* FROM AuthSession S
            JOIN User U ON U.user_id = S.user_id
            WHERE S.channel_user_id = ?
              AND S.revoked_at_utc IS NULL
              AND S.expires_at_utc > ?
              AND U.active = 1
            ORDER BY S.created_at_utc DESC
            LIMIT 1
            """,
            (channel_user_id, moment),
        ).fetchone()

    def authorized_subscription(
        self, channel_user_id: str, sensor_id: int = 1
    ) -> sqlite3.Row | None:
        user = self.authenticated_user(channel_user_id)
        if user is None:
            return None
        return self.connection.execute(
            """
            SELECT * FROM Subscription
            WHERE user_id = ? AND sensor_id = ? AND enabled = 1
            """,
            (user["user_id"], sensor_id),
        ).fetchone()

    def active_channel_for_user(
        self, user_id: int, now: datetime | None = None
    ) -> str | None:
        moment = utc_text(now or utc_now())
        row = self.connection.execute(
            """
            SELECT S.channel_user_id FROM AuthSession S
            JOIN User U ON U.user_id = S.user_id
            WHERE S.user_id = ?
              AND S.revoked_at_utc IS NULL
              AND S.expires_at_utc > ?
              AND U.active = 1
            ORDER BY S.created_at_utc DESC
            LIMIT 1
            """,
            (user_id, moment),
        ).fetchone()
        return None if row is None else str(row["channel_user_id"])

    def save_measurement(
        self, sensor_id: int, measured_at_utc: datetime, value_c: float
    ) -> None:
        timestamp = utc_text(measured_at_utc)
        encrypted = self.cipher.encrypt(sensor_id, timestamp, value_c)
        with self.connection:
            self.connection.execute(
                """
                INSERT INTO Measurement(sensor_id, measured_at_utc, value_enc)
                VALUES(?, ?, ?)
                ON CONFLICT(sensor_id, measured_at_utc)
                DO UPDATE SET value_enc = excluded.value_enc
                """,
                (sensor_id, timestamp, encrypted),
            )

    def latest_measurement(self, sensor_id: int = 1) -> tuple[str, float] | None:
        row = self.connection.execute(
            """
            SELECT measured_at_utc, value_enc FROM Measurement
            WHERE sensor_id = ?
            ORDER BY measured_at_utc DESC LIMIT 1
            """,
            (sensor_id,),
        ).fetchone()
        if row is None:
            return None
        value = self.cipher.decrypt(sensor_id, row["measured_at_utc"], row["value_enc"])
        return row["measured_at_utc"], value

    def history(
        self, minutes: int, sensor_id: int = 1, now: datetime | None = None
    ) -> list[tuple[str, float]]:
        cutoff = utc_text((now or utc_now()) - timedelta(minutes=minutes))
        rows = self.connection.execute(
            """
            SELECT measured_at_utc, value_enc FROM Measurement
            WHERE sensor_id = ? AND measured_at_utc >= ?
            ORDER BY measured_at_utc
            """,
            (sensor_id, cutoff),
        ).fetchall()
        return [
            (
                row["measured_at_utc"],
                self.cipher.decrypt(sensor_id, row["measured_at_utc"], row["value_enc"]),
            )
            for row in rows
        ]

    def limits(self, user_id: int, sensor_id: int = 1) -> tuple[float, float]:
        row = self.connection.execute(
            """
            SELECT lower_c, upper_c FROM Subscription
            WHERE user_id = ? AND sensor_id = ? AND enabled = 1
            """,
            (user_id, sensor_id),
        ).fetchone()
        if row is None:
            raise PermissionError("No access to the sensor")
        return float(row["lower_c"]), float(row["upper_c"])

    def set_limits(
        self, user_id: int, lower_c: float, upper_c: float, sensor_id: int = 1
    ) -> None:
        if not MIN_TEMPERATURE_C <= lower_c < upper_c <= MAX_TEMPERATURE_C:
            raise ValueError("Limits must satisfy -40 <= lower < upper <= 85")
        with self.connection:
            cursor = self.connection.execute(
                """
                UPDATE Subscription SET lower_c = ?, upper_c = ?
                WHERE user_id = ? AND sensor_id = ? AND enabled = 1
                """,
                (lower_c, upper_c, user_id, sensor_id),
            )
        if cursor.rowcount != 1:
            raise PermissionError("No access to the sensor")

    def active_subscriptions(self, sensor_id: int = 1) -> list[sqlite3.Row]:
        return self.connection.execute(
            """
            SELECT user_id, sensor_id, lower_c, upper_c
            FROM Subscription
            WHERE sensor_id = ? AND enabled = 1
            """,
            (sensor_id,),
        ).fetchall()


class ThermoControl:
    """Application service used by any messenger or console adapter."""

    def __init__(
        self,
        repository: Repository,
        source: TemperatureSource | None = None,
        processor: SignalProcessor | None = None,
        sensor_id: int = 1,
    ) -> None:
        self.repository = repository
        self.source = source or TemperatureSource()
        self.processor = processor or SignalProcessor()
        self.sensor_id = sensor_id
        self.last_alerts: list[AlertEvent] = []
        self._violation_flags: dict[tuple[int, int], bool] = {}

    def acquire_at(
        self, t_seconds: float, measured_at_utc: datetime | None = None
    ) -> ProcessedSample:
        measured_at = measured_at_utc or utc_now()
        raw = self.source.value_at(t_seconds)
        processed = self.processor.accept(raw, measured_at)
        if processed is None:
            raise ValueError("The source returned an invalid sample")
        self.repository.save_measurement(
            self.sensor_id, processed.measured_at_utc, processed.filtered_c
        )
        self.last_alerts = self._new_alerts(processed.filtered_c)
        return processed

    def _new_alerts(self, value_c: float) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        for row in self.repository.active_subscriptions(self.sensor_id):
            key = (int(row["user_id"]), int(row["sensor_id"]))
            violation = value_c < row["lower_c"] or value_c > row["upper_c"]
            was_violation = self._violation_flags.get(key, False)
            if violation and not was_violation:
                events.append(
                    AlertEvent(
                        user_id=key[0],
                        sensor_id=key[1],
                        value_c=value_c,
                        lower_c=float(row["lower_c"]),
                        upper_c=float(row["upper_c"]),
                    )
                )
            self._violation_flags[key] = violation
        return events

    def login(self, channel_user_id: str, login: str, password: str) -> str:
        session = self.repository.authenticate(login, password, channel_user_id)
        if session is None:
            return "Неверные учетные данные или вход временно заблокирован."
        return "Вход выполнен. Защищенные команды доступны 24 часа."

    def handle_command(self, channel_user_id: str, text: str) -> str:
        parts = text.strip().split()
        if not parts:
            return "Введите команду."
        command = parts[0].lower()

        if command == "/start":
            return (
                "ТермоКонтроль: /login <логин>, /status, /history [минуты], "
                "/limits [нижняя верхняя], /logout."
            )
        if command == "/login":
            return "После /login <логин> пароль запрашивается защищенным вводом шлюза."
        if command == "/logout":
            if self.repository.logout(channel_user_id):
                return "Сеанс завершен."
            return "Активный сеанс отсутствует."

        user = self.repository.authenticated_user(channel_user_id)
        if user is None:
            return "Требуется вход: /login <логин>."
        subscription = self.repository.authorized_subscription(
            channel_user_id, self.sensor_id
        )
        if subscription is None:
            return "Нет права доступа к выбранному датчику."

        if command == "/status":
            latest = self.repository.latest_measurement(self.sensor_id)
            if latest is None:
                return "Измерений пока нет."
            timestamp, value = latest
            return f"Температура: {value:.2f} °C; время UTC: {timestamp}."

        if command == "/history":
            minutes = self._minutes(parts)
            if minutes is None:
                return "Интервал должен быть целым числом от 1 до 1440 минут."
            values = self.repository.history(minutes, self.sensor_id)
            if not values:
                return "За указанный интервал измерений нет."
            shown = values[-10:]
            lines = [f"{timestamp}: {value:.2f} °C" for timestamp, value in shown]
            return "Последние измерения:\n" + "\n".join(lines)

        if command == "/limits":
            if len(parts) == 1:
                lower, upper = self.repository.limits(user["user_id"], self.sensor_id)
                return f"Границы: {lower:.1f}...{upper:.1f} °C."
            if len(parts) != 3:
                return "Формат: /limits <нижняя> <верхняя>."
            try:
                lower, upper = float(parts[1]), float(parts[2])
                self.repository.set_limits(
                    user["user_id"], lower, upper, self.sensor_id
                )
            except ValueError:
                return "Границы должны удовлетворять -40 <= нижняя < верхняя <= 85."
            return f"Границы обновлены: {lower:.1f}...{upper:.1f} °C."

        return "Неизвестная команда. Используйте /start."

    @staticmethod
    def _minutes(parts: list[str]) -> int | None:
        if len(parts) == 1:
            return 60
        if len(parts) != 2:
            return None
        try:
            value = int(parts[1])
        except ValueError:
            return None
        return value if 1 <= value <= 1440 else None


def format_samples(samples: Iterable[ProcessedSample]) -> str:
    lines = ["t, raw_c, buffer, average_c"]
    for index, sample in enumerate(samples):
        lines.append(
            f"{index:>2}, {sample.raw_c:>5.1f}, {sample.buffer_size:>3}, "
            f"{sample.filtered_c:>6.2f}"
        )
    return "\n".join(lines)
