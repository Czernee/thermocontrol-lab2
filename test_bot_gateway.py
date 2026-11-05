from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from bot_gateway import BotApiError, BotGateway
from thermocontrol import MeasurementCipher, PasswordHasher, Repository, ThermoControl


class FakeApi:
    def __init__(self) -> None:
        self.sent: list[tuple[int, str]] = []
        self.deleted: list[tuple[int, int]] = []
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
        root = Path(self.temp.name)
        self.repository = Repository(
            root / "test.sqlite3",
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


if __name__ == "__main__":
    unittest.main()
