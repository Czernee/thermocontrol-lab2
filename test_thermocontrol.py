from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from thermocontrol import (
    MeasurementCipher,
    HistoryChart,
    PasswordHasher,
    Repository,
    SignalProcessor,
    TemperatureSource,
    ThermoControl,
    format_user_time,
    utc_text,
)


class ThermoControlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="thermocontrol-tests-")
        db_path = Path(self.temp.name) / "test.sqlite3"
        cipher = MeasurementCipher(AESGCM.generate_key(bit_length=256))
        self.repository = Repository(
            db_path, cipher, PasswordHasher(iterations=1_000)
        )
        self.repository.initialize()
        self.user_id = self.repository.provision_user("student", "Strong-pass-2")
        self.application = ThermoControl(self.repository)
        self.base = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)

    def tearDown(self) -> None:
        self.repository.close()
        self.temp.cleanup()

    def test_virtual_sensor_control_points(self) -> None:
        self.assertAlmostEqual(TemperatureSource.value_at(0), 22.0)
        self.assertAlmostEqual(TemperatureSource.value_at(30), 24.0)
        self.assertAlmostEqual(TemperatureSource.value_at(90), 20.0)

    def test_invalid_sample_does_not_enter_buffer(self) -> None:
        processor = SignalProcessor()
        self.assertIsNone(processor.accept(100.0, self.base))
        self.assertEqual(processor.buffer_size, 0)

    def test_moving_average_uses_five_latest_samples(self) -> None:
        processor = SignalProcessor()
        result = None
        for index, value in enumerate([20, 21, 22, 23, 24, 25]):
            result = processor.accept(value, self.base + timedelta(seconds=index))
        self.assertIsNotNone(result)
        self.assertEqual(result.filtered_c, 23.0)
        self.assertEqual(result.buffer_size, 5)

    def test_login_permission_logout_cycle(self) -> None:
        channel = "channel-1"
        self.assertIn("Требуется вход", self.application.handle_command(channel, "/status"))
        self.assertIn("Неверные", self.application.login(channel, "student", "wrong-pass"))
        self.assertIn("Вход выполнен", self.application.login(channel, "student", "Strong-pass-2"))

        self.application.acquire_at(0, self.base)
        self.assertIn("22.00", self.application.handle_command(channel, "/status"))
        self.assertIn("Сеанс завершен", self.application.handle_command(channel, "/logout"))
        self.assertIn("Требуется вход", self.application.handle_command(channel, "/status"))

    def test_status_uses_readable_moscow_time(self) -> None:
        channel = "channel-time"
        self.application.login(channel, "student", "Strong-pass-2")
        moment = datetime(2026, 11, 5, 14, 10, 24, tzinfo=timezone.utc)
        self.application.acquire_at(3, moment)

        response = self.application.handle_command(channel, "/status")

        self.assertIn("Температура: 22.60 °C", response)
        self.assertIn("05.11.2026 17:10:24 МСК", response)
        self.assertNotIn("T14:10:24Z", response)

    def test_password_reset_revokes_sessions(self) -> None:
        channel = "channel-reset"
        self.assertIn(
            "Вход выполнен",
            self.application.login(channel, "student", "Strong-pass-2"),
        )

        self.assertTrue(self.repository.set_password("student", "New-strong-pass-3"))

        self.assertIsNone(self.repository.authenticated_user(channel))
        self.assertIn(
            "Неверные",
            self.application.login(channel, "student", "Strong-pass-2"),
        )
        self.assertIn(
            "Вход выполнен",
            self.application.login(channel, "student", "New-strong-pass-3"),
        )

    def test_history_uses_readable_user_time(self) -> None:
        channel = "channel-history"
        self.application.login(channel, "student", "Strong-pass-2")
        moment = datetime.now(timezone.utc).replace(microsecond=0)
        self.application.acquire_at(0, moment)

        response = self.application.handle_command(channel, "/history 1")
        expected = format_user_time(utc_text(moment), "Europe/Moscow")

        self.assertIn(expected, response)
        self.assertNotIn("T", response)

    def test_history_chart_is_png_with_summary(self) -> None:
        channel = "channel-chart"
        self.application.login(channel, "student", "Strong-pass-2")
        moment = datetime.now(timezone.utc).replace(microsecond=0)
        for second in range(3):
            self.application.acquire_at(second, moment + timedelta(seconds=second))

        result = self.application.history_chart(channel, "/history 1")

        self.assertIsInstance(result, HistoryChart)
        assert isinstance(result, HistoryChart)
        self.assertTrue(result.png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertIn("3 измерений", result.caption)
        self.assertIn("Минимум", result.caption)
        self.assertIn("максимум", result.caption)
        self.assertIn("среднее", result.caption)

    def test_history_chart_requires_login_and_sensor_permission(self) -> None:
        channel = "channel-chart-access"
        self.assertIn("Требуется вход", self.application.history_chart(channel, "/history 1"))

        self.application.login(channel, "student", "Strong-pass-2")
        with self.repository.connection:
            self.repository.connection.execute(
                "UPDATE Subscription SET enabled = 0 WHERE user_id = ?",
                (self.user_id,),
            )

        self.assertIn(
            "Нет права доступа",
            self.application.history_chart(channel, "/history 1"),
        )

    def test_history_chart_reports_invalid_interval_and_empty_history(self) -> None:
        channel = "channel-chart-errors"
        self.application.login(channel, "student", "Strong-pass-2")

        self.assertIn(
            "от 1 до 1440",
            self.application.history_chart(channel, "/history нет"),
        )
        self.assertIn(
            "измерений нет",
            self.application.history_chart(channel, "/history 1"),
        )

    def test_authorization_is_separate_from_authentication(self) -> None:
        channel = "channel-2"
        self.application.login(channel, "student", "Strong-pass-2")
        with self.repository.connection:
            self.repository.connection.execute(
                "UPDATE Subscription SET enabled = 0 WHERE user_id = ?",
                (self.user_id,),
            )
        self.assertIn(
            "Нет права доступа",
            self.application.handle_command(channel, "/status"),
        )

    def test_encrypted_measurement_round_trip(self) -> None:
        self.application.acquire_at(3, self.base)
        row = self.repository.connection.execute(
            "SELECT value_enc FROM Measurement LIMIT 1"
        ).fetchone()
        self.assertNotIn(b"22.6", row["value_enc"])
        _, value = self.repository.latest_measurement()
        self.assertAlmostEqual(value, 22.6)

    def test_alert_is_created_only_on_new_violation(self) -> None:
        self.repository.set_limits(self.user_id, 21.0, 22.3)
        for second in range(4):
            self.application.acquire_at(second, self.base + timedelta(seconds=second))
        self.assertEqual(len(self.application.last_alerts), 1)
        self.application.acquire_at(4, self.base + timedelta(seconds=4))
        self.assertEqual(self.application.last_alerts, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
