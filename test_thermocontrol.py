from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from thermocontrol import (
    MeasurementCipher,
    PasswordHasher,
    Repository,
    SignalProcessor,
    TemperatureSource,
    ThermoControl,
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
        self.assertEqual(result.buffer_size, 6)

    def test_login_permission_logout_cycle(self) -> None:
        channel = "channel-1"
        self.assertIn("Требуется вход", self.application.handle_command(channel, "/status"))
        self.assertIn("Неверные", self.application.login(channel, "student", "wrong-pass"))
        self.assertIn("Вход выполнен", self.application.login(channel, "student", "Strong-pass-2"))

        self.application.acquire_at(0, self.base)
        self.assertIn("22.00", self.application.handle_command(channel, "/status"))
        self.assertIn("Сеанс завершен", self.application.handle_command(channel, "/logout"))
        self.assertIn("Требуется вход", self.application.handle_command(channel, "/status"))

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
