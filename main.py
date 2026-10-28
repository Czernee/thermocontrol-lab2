"""Console gateway and reproducible demo for Laboratory work 2."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import getpass
from pathlib import Path
import tempfile

from thermocontrol import (
    MeasurementCipher,
    PasswordHasher,
    Repository,
    ThermoControl,
    format_samples,
    load_or_create_key,
)


def build_application(db_path: Path, key_path: Path) -> tuple[Repository, ThermoControl]:
    key = load_or_create_key(key_path)
    repository = Repository(db_path, MeasurementCipher(key))
    repository.initialize()
    return repository, ThermoControl(repository)


def run_demo() -> None:
    """Runs without network access and leaves no database or secret behind."""

    with tempfile.TemporaryDirectory(prefix="thermocontrol-demo-") as directory:
        root = Path(directory)
        key = load_or_create_key(root / "demo.key")
        repository = Repository(
            root / "demo.sqlite3",
            MeasurementCipher(key),
            PasswordHasher(),
        )
        repository.initialize()
        repository.provision_user("student", "Lab2-demo!")
        application = ThermoControl(repository)

        base_time = datetime(2026, 10, 28, 12, 0, tzinfo=timezone.utc)
        samples = [
            application.acquire_at(second, base_time + timedelta(seconds=second))
            for second in range(7)
        ]

        print("=== ПРИЕМ И ПРЕДВАРИТЕЛЬНАЯ ОБРАБОТКА ===")
        print(format_samples(samples))
        print()
        print("=== АУТЕНТИФИКАЦИЯ И АВТОРИЗАЦИЯ ===")
        channel = "console-user-1"
        print("Пользователь: /status")
        print("Система:", application.handle_command(channel, "/status"))
        print("Пользователь: /login student ******** (неверный пароль)")
        print("Система:", application.login(channel, "student", "wrong-pass"))
        print("Пользователь: /login student ********")
        print("Система:", application.login(channel, "student", "Lab2-demo!"))
        print("Пользователь: /status")
        print("Система:", application.handle_command(channel, "/status"))
        print("Пользователь: /limits 21 23")
        print("Система:", application.handle_command(channel, "/limits 21 23"))
        print("Пользователь: /logout")
        print("Система:", application.handle_command(channel, "/logout"))
        print("Пользователь: /status")
        print("Система:", application.handle_command(channel, "/status"))
        repository.close()


def interactive(db_path: Path, key_path: Path) -> None:
    repository, application = build_application(db_path, key_path)
    channel = "local-console-user"
    print("ТермоКонтроль. /start - справка; exit - завершение.")
    try:
        while True:
            command = input("Пользователь> ").strip()
            if command.lower() in {"exit", "quit"}:
                break
            parts = command.split()
            if parts and parts[0].lower() == "/login" and len(parts) == 2:
                password = getpass.getpass("Пароль (не отображается)> ")
                print("Система>", application.login(channel, parts[1], password))
            else:
                print("Система>", application.handle_command(channel, command))
    finally:
        repository.close()


def provision(db_path: Path, key_path: Path, login: str) -> None:
    repository, _ = build_application(db_path, key_path)
    try:
        password = getpass.getpass("Новый пароль (минимум 8 символов)> ")
        confirmation = getpass.getpass("Повторите пароль> ")
        if password != confirmation:
            raise SystemExit("Пароли не совпадают.")
        user_id = repository.provision_user(login, password)
        print(f"Создан пользователь {login!r}, внутренний user_id={user_id}.")
    finally:
        repository.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="ТермоКонтроль: учебная версия")
    parser.add_argument("--demo", action="store_true", help="запустить демонстрацию")
    parser.add_argument("--create-user", metavar="LOGIN", help="создать учетную запись")
    parser.add_argument("--db", type=Path, default=Path("thermocontrol.sqlite3"))
    parser.add_argument("--key", type=Path, default=Path("thermocontrol.key"))
    arguments = parser.parse_args()

    if arguments.demo:
        run_demo()
    elif arguments.create_user:
        provision(arguments.db, arguments.key, arguments.create_user)
    else:
        interactive(arguments.db, arguments.key)


if __name__ == "__main__":
    main()
