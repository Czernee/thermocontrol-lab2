"""External message gateway for the ThermoControl application."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from thermocontrol import (
    AlertEvent,
    MeasurementCipher,
    Repository,
    ThermoControl,
    load_or_create_key,
)


LOGIN_TIMEOUT_S = 120
MAX_MESSAGE_LENGTH = 4000


class BotApiError(RuntimeError):
    """A sanitized Bot API error that never contains the access token."""


def load_bot_token(path: str | Path) -> str:
    """Reads the API token from a local file or a mounted Docker secret."""

    token_path = Path(path)
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        raise SystemExit(f"Файл токена не найден: {token_path}") from None
    if not token:
        raise SystemExit(f"Файл токена пуст: {token_path}")
    return token


class BotApiClient:
    """Small HTTPS client for the message platform Bot API."""

    def __init__(
        self,
        token: str,
        opener: Callable[..., Any] = urlopen,
    ) -> None:
        if not token:
            raise ValueError("Bot API token is empty")
        self._base_url = f"https://api.telegram.org/bot{token}/"
        self._opener = opener

    def call(
        self,
        method: str,
        payload: dict[str, Any] | None = None,
        request_timeout: int = 10,
    ) -> Any:
        encoded: dict[str, str] = {}
        for key, value in (payload or {}).items():
            if value is None:
                continue
            if isinstance(value, (dict, list)):
                encoded[key] = json.dumps(value, ensure_ascii=False)
            elif isinstance(value, bool):
                encoded[key] = "true" if value else "false"
            else:
                encoded[key] = str(value)
        request = Request(
            self._base_url + method,
            data=urlencode(encoded).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with self._opener(request, timeout=request_timeout) as response:
                result = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            raise BotApiError(f"Bot API returned HTTP {error.code}") from None
        except (URLError, TimeoutError, json.JSONDecodeError):
            raise BotApiError("Bot API is temporarily unavailable") from None
        if not result.get("ok"):
            description = str(result.get("description", "request rejected"))
            raise BotApiError(f"Bot API rejected the request: {description}")
        return result.get("result")

    def get_me(self) -> dict[str, Any]:
        return dict(self.call("getMe"))

    def delete_webhook(self) -> None:
        self.call("deleteWebhook", {"drop_pending_updates": False})

    def set_commands(self) -> None:
        commands = [
            {"command": "start", "description": "справка"},
            {"command": "login", "description": "вход в систему"},
            {"command": "status", "description": "текущая температура"},
            {"command": "history", "description": "история измерений"},
            {"command": "limits", "description": "границы уведомлений"},
            {"command": "logout", "description": "завершить сеанс"},
            {"command": "cancel", "description": "отменить ввод пароля"},
        ]
        self.call("setMyCommands", {"commands": commands})

    def get_updates(
        self, offset: int | None = None, timeout: int = 1
    ) -> list[dict[str, Any]]:
        result = self.call(
            "getUpdates",
            {
                "offset": offset,
                "timeout": timeout,
                "allowed_updates": ["message"],
            },
            request_timeout=timeout + 5,
        )
        return list(result)

    def send_message(self, chat_id: int, text: str) -> None:
        self.call(
            "sendMessage",
            {"chat_id": chat_id, "text": text[:MAX_MESSAGE_LENGTH]},
        )

    def delete_message(self, chat_id: int, message_id: int) -> None:
        self.call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})


@dataclass(frozen=True)
class PendingLogin:
    login: str
    expires_at: float


class BotGateway:
    """Translates private chat messages into application service calls."""

    def __init__(
        self,
        api: BotApiClient,
        application: ThermoControl,
        repository: Repository,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.api = api
        self.application = application
        self.repository = repository
        self.clock = clock
        self._pending_logins: dict[str, PendingLogin] = {}

    def handle_update(self, update: dict[str, Any]) -> None:
        # Шлюз принимает только обычные текстовые сообщения пользователя.
        message = update.get("message")
        if not isinstance(message, dict):
            return
        text = message.get("text")
        sender = message.get("from")
        chat = message.get("chat")
        if (
            not isinstance(text, str)
            or not isinstance(sender, dict)
            or not isinstance(chat, dict)
        ):
            return
        if sender.get("is_bot"):
            return

        chat_id = int(chat["id"])
        # Пароль разрешено передавать только в личном диалоге.
        if chat.get("type") != "private":
            self.api.send_message(chat_id, "Для входа используйте личный чат с ботом.")
            return

        # Внутри ядра используется нейтральный идентификатор канала,
        # поэтому оно не зависит от конкретного мессенджера.
        channel_user_id = f"msg:{int(sender['id'])}"
        raw_text = text
        command_text = self._normalize_command(raw_text)
        command = command_text.split(maxsplit=1)[0].lower() if command_text else ""
        pending = self._pending_logins.get(channel_user_id)

        # Незавершенный вход хранится в памяти не более 120 секунд.
        if pending is not None and self.clock() > pending.expires_at:
            del self._pending_logins[channel_user_id]
            pending = None
            if not command_text.startswith("/"):
                self.api.send_message(
                    chat_id,
                    "Время ввода пароля истекло. Повторите /login <логин>.",
                )
                return

        if pending is not None and command != "/cancel":
            # Сообщение удаляется до проверки, чтобы пароль не оставался в чате.
            password_deleted = self._delete_password_message(
                chat_id, int(message["message_id"])
            )
            password = raw_text
            try:
                response = self.application.login(
                    channel_user_id, pending.login, password
                )
            finally:
                # Состояние и локальная ссылка на пароль очищаются при любом исходе.
                password = ""
                del self._pending_logins[channel_user_id]
            if not password_deleted:
                response += " Не удалось удалить сообщение с паролем; удалите его вручную."
            self.api.send_message(chat_id, response)
            return

        # Пользователь может явно отменить незавершенную процедуру входа.
        if command == "/cancel":
            removed = self._pending_logins.pop(channel_user_id, None)
            response = "Ввод пароля отменен." if removed else "Нет незавершенного входа."
            self.api.send_message(chat_id, response)
            return

        # /login только запоминает логин; пароль ожидается отдельным сообщением.
        if command == "/login":
            parts = command_text.split()
            if len(parts) != 2:
                self.api.send_message(
                    chat_id,
                    "Формат: /login <логин>. "
                    "Пароль отправляется следующим сообщением.",
                )
                return
            self._pending_logins[channel_user_id] = PendingLogin(
                login=parts[1],
                expires_at=self.clock() + LOGIN_TIMEOUT_S,
            )
            self.api.send_message(
                chat_id,
                "Отправьте пароль отдельным сообщением в течение 120 секунд. "
                "После проверки сообщение будет удалено.",
            )
            return

        # Все остальные команды обрабатывает независимое от мессенджера ядро.
        response = self.application.handle_command(channel_user_id, command_text)
        self.api.send_message(chat_id, response)

    def deliver_alerts(self, events: list[AlertEvent]) -> None:
        for event in events:
            channel = self.repository.active_channel_for_user(event.user_id)
            if channel is None or not channel.startswith("msg:"):
                continue
            try:
                chat_id = int(channel.split(":", 1)[1])
            except ValueError:
                continue
            try:
                self.api.send_message(
                    chat_id,
                    "Предупреждение: температура "
                    f"{event.value_c:.2f} °C вышла за границы "
                    f"{event.lower_c:.1f}...{event.upper_c:.1f} °C.",
                )
            except BotApiError as error:
                print(f"Шлюз сообщений: уведомление не отправлено ({error}).")

    def _delete_password_message(self, chat_id: int, message_id: int) -> bool:
        try:
            self.api.delete_message(chat_id, message_id)
        except BotApiError:
            return False
        return True

    @staticmethod
    def _normalize_command(text: str) -> str:
        stripped = text.strip()
        if not stripped.startswith("/"):
            return stripped
        parts = stripped.split(maxsplit=1)
        command = parts[0].split("@", 1)[0]
        return command if len(parts) == 1 else f"{command} {parts[1]}"


def initialize_api(api: BotApiClient, attempts: int = 5) -> dict[str, Any]:
    delay = 1
    for attempt in range(1, attempts + 1):
        try:
            api.delete_webhook()
            api.set_commands()
            return api.get_me()
        except BotApiError:
            if attempt == attempts:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 5)
    raise AssertionError("unreachable")


def run_long_polling(
    api: BotApiClient,
    gateway: BotGateway,
    application: ThermoControl,
) -> None:
    offset: int | None = None
    # monotonic не зависит от перевода системных часов, UTC нужен для БД.
    start_monotonic = time.monotonic()
    start_utc = datetime.now(timezone.utc)
    next_sample = 0
    retry_delay = 1

    while True:
        elapsed = int(time.monotonic() - start_monotonic)
        # Если сетевой запрос занял больше секунды, создаются все пропущенные отсчеты.
        while next_sample <= elapsed:
            measured_at = start_utc + timedelta(seconds=next_sample)
            application.acquire_at(next_sample, measured_at)
            # После каждого отсчета проверяются новые выходы за заданные границы.
            gateway.deliver_alerts(application.last_alerts)
            next_sample += 1

        try:
            # Короткий long polling чередует прием сообщений с измерениями.
            updates = api.get_updates(offset=offset, timeout=1)
            retry_delay = 1
        except BotApiError as error:
            # Временная ошибка сети не останавливает измерения и длинный опрос.
            print(f"Шлюз сообщений: {error}. Повтор через {retry_delay} с.")
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 5)
            continue

        for update in sorted(updates, key=lambda item: int(item.get("update_id", 0))):
            update_id = int(update.get("update_id", 0))
            if offset is not None and update_id < offset:
                continue
            try:
                gateway.handle_update(update)
            except BotApiError as error:
                print(f"Шлюз сообщений: {error}.")
            finally:
                # Следующий запрос начинает чтение после уже обработанного update_id.
                offset = update_id + 1


def run_bot(db_path: Path, key_path: Path, token_path: Path) -> None:
    token = load_bot_token(token_path)
    key = load_or_create_key(key_path)
    repository = Repository(db_path, MeasurementCipher(key))
    repository.initialize()
    try:
        application = ThermoControl(repository)
        api = BotApiClient(token)
        identity = initialize_api(api)
        username = identity.get("username", "unknown")
        print(f"Шлюз сообщений запущен: @{username}")
        gateway = BotGateway(api, application, repository)
        run_long_polling(api, gateway, application)
    finally:
        repository.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="ТермоКонтроль: шлюз сообщений")
    parser.add_argument("--db", type=Path, default=Path("data/thermocontrol.sqlite3"))
    parser.add_argument("--key", type=Path, default=Path("data/thermocontrol.key"))
    parser.add_argument(
        "--token-file",
        type=Path,
        default=Path("secrets/bot_token.txt"),
    )
    arguments = parser.parse_args()
    run_bot(arguments.db, arguments.key, arguments.token_file)


if __name__ == "__main__":
    main()
