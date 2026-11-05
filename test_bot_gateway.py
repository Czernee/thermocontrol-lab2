from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from bot_gateway import BotApiClient, BotApiError, BotGateway, load_bot_token
from thermocontrol import MeasurementCipher, PasswordHasher, Repository, ThermoControl


class FakeApi:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str]] = []
        self.deleted: list[tuple[int, int]] = []
        self.photos: list[tuple[int, bytes, str]] = []
        self.fail_delete = False
        self.fail_send = False

    def send_message(self, chat_id: int, text: str) -> None:
        if self.fail_send:
            raise BotApiError("temporary failure")
        self.sent.append((chat_id, text))

    def delete_message(self, chat_id: int, message_id: int) -> None:
        if self.fail_delete:
            raise BotApiError("temporary failure")
        self.deleted.append((chat_id, message_id))

    def send_photo(self, chat_id: int, photo: bytes, caption: str) -> None:
        self.photos.append((chat_id, photo, caption))


def update(
    text: str,
    message_id: int,
    user_id: int = 100,
    chat_type: str = "private",
) -> dict:
    return {
        "update_id": message_id,
        "message": {
            "message_id": message_id,
            "text": text,
            "from": {"id": user_id, "is_bot": False},
            "chat": {"id": user_id, "type": chat_type},
        },
    }


class BotGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="thermocontrol-bot-test-")
        self.root = Path(self.temp.name)
        self.repository = Repository(
            self.root / "test.sqlite3",
            MeasurementCipher(b"t" * 32),
            PasswordHasher(iterations=1_000),
        )
        self.repository.initialize()
        self.repository.provision_user("student", "correct-pass")
        self.application = ThermoControl(self.repository)
        self.application.acquire_at(0, datetime(2026, 11, 6, tzinfo=timezone.utc))
        self.api = FakeApi()
        self.now = 10.0
        self.gateway = BotGateway(
            self.api,
            self.application,
            self.repository,
            clock=lambda: self.now,
        )

    def tearDown(self) -> None:
        self.repository.close()
        self.temp.cleanup()

    def test_login_password_is_deleted_and_status_becomes_available(self) -> None:
        self.gateway.handle_update(update("/login student", 1))
        self.gateway.handle_update(update("correct-pass", 2))
        self.gateway.handle_update(update("/status", 3))

        self.assertEqual(self.api.deleted, [(100, 2)])
        responses = "\n".join(text for _, text in self.api.sent)
        self.assertIn("Вход выполнен", responses)
        self.assertIn("Температура", responses)
        self.assertNotIn("correct-pass", responses)

    def test_history_is_sent_as_png_chart(self) -> None:
        self.gateway.handle_update(update("/login student", 1))
        self.gateway.handle_update(update("correct-pass", 2))
        self.gateway.handle_update(update("/history 1440", 3))

        self.assertEqual(len(self.api.photos), 1)
        chat_id, image, caption = self.api.photos[0]
        self.assertEqual(chat_id, 100)
        self.assertTrue(image.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn("Минимум", caption)

    def test_history_error_is_sent_as_text_instead_of_photo(self) -> None:
        self.gateway.handle_update(update("/history 1", 1))

        self.assertEqual(self.api.photos, [])
        self.assertIn("Требуется вход", self.api.sent[-1][1])

    def test_bot_api_photo_uses_multipart_request(self) -> None:
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return None

            def read(self):
                return b'{"ok": true, "result": {}}'

        def opener(request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return Response()

        client = BotApiClient("example-token", opener=opener)
        client.send_photo(100, b"\x89PNG-test", "Сводка")

        request = captured["request"]
        self.assertTrue(request.full_url.endswith("/sendPhoto"))
        self.assertIn("multipart/form-data", request.headers["Content-type"])
        self.assertIn(b'name="photo"', request.data)
        self.assertIn(b"\x89PNG-test", request.data)

    def test_login_with_password_in_command_is_rejected(self) -> None:
        self.gateway.handle_update(update("/login student correct-pass", 1))
        self.assertIn("Формат: /login <логин>", self.api.sent[-1][1])
        self.assertEqual(self.api.deleted, [])

    def test_group_login_is_rejected(self) -> None:
        self.gateway.handle_update(update("/login student", 1, chat_type="group"))
        self.assertIn("личный чат", self.api.sent[-1][1])

    def test_pending_login_expires(self) -> None:
        self.gateway.handle_update(update("/login student", 1))
        self.now += 121
        self.gateway.handle_update(update("correct-pass", 2))
        self.assertIn("истекло", self.api.sent[-1][1])
        self.assertEqual(self.api.deleted, [])

    def test_password_starting_with_slash_is_accepted(self) -> None:
        self.repository.provision_user("slash-user", "/Secret123")
        self.gateway.handle_update(update("/login slash-user", 1))
        self.gateway.handle_update(update("/Secret123", 2))
        self.assertIn("Вход выполнен", self.api.sent[-1][1])

    def test_password_deletion_failure_is_reported_without_password(self) -> None:
        self.gateway.handle_update(update("/login student", 1))
        self.api.fail_delete = True
        self.gateway.handle_update(update("correct-pass", 2))
        response = self.api.sent[-1][1]
        self.assertIn("удалите его вручную", response)
        self.assertNotIn("correct-pass", response)

    def test_notification_failure_does_not_escape(self) -> None:
        self.gateway.handle_update(update("/login student", 1))
        self.gateway.handle_update(update("correct-pass", 2))
        self.api.fail_send = True
        event = self.application._new_alerts(90.0)[0]
        self.gateway.deliver_alerts([event])

    def test_repeated_timestamp_updates_existing_measurement(self) -> None:
        moment = datetime(2026, 11, 6, tzinfo=timezone.utc)
        self.application.acquire_at(1, moment)
        self.application.acquire_at(2, moment)
        count = self.repository.connection.execute(
            "SELECT COUNT(*) FROM Measurement WHERE measured_at_utc = ?",
            ("2026-11-06T00:00:00Z",),
        ).fetchone()[0]
        self.assertEqual(count, 1)

    def test_inactive_user_has_no_alert_channel(self) -> None:
        self.gateway.handle_update(update("/login student", 1))
        self.gateway.handle_update(update("correct-pass", 2))
        with self.repository.connection:
            self.repository.connection.execute(
                "UPDATE User SET active = 0 WHERE login = ?", ("student",)
            )
        user_id = self.repository.connection.execute(
            "SELECT user_id FROM User WHERE login = ?", ("student",)
        ).fetchone()[0]
        self.assertIsNone(self.repository.active_channel_for_user(user_id))

    def test_bot_token_is_loaded_from_secret_file(self) -> None:
        token_file = self.root / "bot_token"
        token_file.write_text("  example-token\n", encoding="utf-8")
        self.assertEqual(load_bot_token(token_file), "example-token")

    def test_missing_bot_token_file_is_rejected(self) -> None:
        with self.assertRaisesRegex(SystemExit, "Файл токена не найден"):
            load_bot_token(self.root / "missing-token")

    def test_empty_bot_token_file_is_rejected(self) -> None:
        token_file = self.root / "empty-token"
        token_file.write_text("\n", encoding="utf-8")
        with self.assertRaisesRegex(SystemExit, "Файл токена пуст"):
            load_bot_token(token_file)


if __name__ == "__main__":
    unittest.main()
