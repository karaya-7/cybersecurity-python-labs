"""Завдання 3: Безпечне хешування, CSV-база та JSON-логування.

Варіант 10: алгоритм sha3_384, мінімальна довжина пароля 10.
"""

import csv
import hashlib
import json
import sys
from datetime import datetime
from functools import wraps
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from shared.student import (  # noqa: E402
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

HASH_ALGORITHM = "sha3_384"
MIN_PASSWORD_LENGTH = 10

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
USERS_CSV = DATA_DIR / "users.csv"
LOG_JSON = DATA_DIR / "log.json"

PERSONAL_SALT = str(VARIANT_NUMBER).zfill(5)


# винятки
class ValidationError(Exception):
    """Помилка валідації пароля."""


# хешування
def generate_hash(password: str, salt: str = "00000") -> str:
    """Повертає hex-хеш від конкатенації пароля та солі.

    :raises ValueError: якщо пароль або сіль порожні.
    :raises ValidationError: якщо пароль коротший за MIN_PASSWORD_LENGTH.
    """
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(
            f"Пароль коротший за мінімальну довжину "
            f"({MIN_PASSWORD_LENGTH} символів)."
        )

    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update((password + salt).encode("utf-8"))
    return hasher.hexdigest()


def log_event(func):
    """Записує кожну спробу входу у log.json."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        username = args[0] if args else kwargs.get("username", "unknown")
        result = "failure"
        try:
            outcome = func(*args, **kwargs)
            result = "success" if outcome is True else "failure"
            return outcome
        except Exception:
            result = "failure"
            raise
        finally:
            _write_log(username, result, args, kwargs)

    return wrapper


def _write_log(username: str, result: str, args: tuple, kwargs: dict) -> None:
    """Записує подію у JSON-файл (створює, якщо немає)."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    record = {
        "event": "login",
        "user": username,
        "result": result,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "args": [str(a) for a in args],
        "kwargs": {k: str(v) for k, v in kwargs.items()},
    }

    data = []
    if LOG_JSON.exists():
        try:
            with LOG_JSON.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list):
                data = [data]
        except (json.JSONDecodeError, OSError):
            data = []

    data.append(record)

    with LOG_JSON.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


USERS_TO_REGISTER = (
    ("iot_admin", "IotAdm1n@2024"),
    ("mobile_sec", "MobSec#2024A"),
    ("web_dev01", "WebDev!2024x"),
    ("api_user01", "ApiUsr@2024z"),
    ("net_eng01", "NetEng#2024Q"),
    ("sec_audit", "SecAud!t2024"),
    ("cloud_ops", "CloudOp@2024"),
    ("data_prot", "DataProt#24"),
    ("soc_analyst", "SocAn@lyst24"),
    ("ciso_office", "CisoOff!2024"),
)


def create_user(username: str, password: str) -> tuple[str, str]:
    """Повертає (username, hash_value) з використанням персональної солі."""
    hash_value = generate_hash(password, PERSONAL_SALT)
    return username, hash_value


def create_users(users_list) -> None:
    """Створює CSV-базу користувачів."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with USERS_CSV.open("w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
            for username, password in users_list:
                try:
                    user_record = create_user(username, password)
                except (ValidationError, ValueError) as exc:
                    print(f"[!] Пропущено {username}: {exc}")
                    continue
                writer.writerow(user_record)
        print(f"[+] Базу користувачів збережено у {USERS_CSV}")
    except PermissionError as exc:
        print(f"[!] Немає прав на запис у {USERS_CSV}: {exc}")
        raise
    except OSError as exc:
        print(f"[!] Помилка введення-виведення: {exc}")
        raise


def read_users_db() -> list[tuple[str, str]]:
    """Зчитує CSV-базу користувачів."""
    if not USERS_CSV.exists():
        raise FileNotFoundError(f"Файл {USERS_CSV} не знайдено.")

    users_db: list[tuple[str, str]] = []
    try:
        with USERS_CSV.open("r", encoding="utf-8", newline="") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if header is None:
                return users_db
            for row in reader:
                if len(row) >= 2:
                    users_db.append((row[0], row[1]))
    except PermissionError as exc:
        print(f"[!] Немає прав на читання: {exc}")
        raise
    except OSError as exc:
        print(f"[!] Помилка читання: {exc}")
        raise
    return users_db


def print_users_table(users_db: list[tuple[str, str]]) -> None:
    """Друкує базу у вигляді таблиці."""
    print(f"\n{'Логін':<20}{'Хеш пароля':<50}")
    print("-" * 70)
    for username, hash_value in users_db:
        print(f"{username:<20}{hash_value:<50}")
    print("-" * 70)


# --- Автентифікація ---
@log_event
def login(username: str, password: str) -> bool:
    """Перевіряє логін та пароль користувача.

    :raises ValueError: якщо логін або пароль порожні.
    """
    if not username or not password:
        raise ValueError("Логін та пароль не можуть бути порожніми.")

    users_db = read_users_db()
    user_map = dict(users_db)

    if username not in user_map:
        return False

    try:
        computed = generate_hash(password, PERSONAL_SALT)
    except (ValidationError, ValueError):
        return False

    return user_map[username] == computed


def main() -> None:
    """Демонстрація роботи завдання 3."""
    print("=" * 80)
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | "
        f"Варіант: {VARIANT_NUMBER}"
    )
    print(
        f"Завдання 3: Хешування ({HASH_ALGORITHM}), CSV-база, "
        f"JSON-логування"
    )
    print(f"Персональна сіль: {PERSONAL_SALT}")
    print("=" * 80)

    try:
        create_users(USERS_TO_REGISTER)
    except (PermissionError, OSError) as exc:
        print(f"[!] Не вдалося створити базу: {exc}")
        return

    try:
        users_db = read_users_db()
    except FileNotFoundError as exc:
        print(f"[!] {exc}")
        return
    print_users_table(users_db)

    print("\n--- Перевірка автентифікації ---")
    attempts = [
        ("iot_admin", "IotAdm1n@2024"),
        ("iot_admin", "WrongPassword1!"),
        ("unknown", "SomePassword1!"),
        ("web_dev01", ""),
    ]

    for username, password in attempts:
        try:
            result = login(username, password)
            status = "SUCCESS" if result else "FAILURE"
            print(f"login({username!r}) -> {status}")
        except ValueError as exc:
            print(f"login({username!r}) -> ValueError: {exc}")
        except FileNotFoundError as exc:
            print(f"login({username!r}) -> FileNotFoundError: {exc}")
        except PermissionError as exc:
            print(f"login({username!r}) -> PermissionError: {exc}")
        except OSError as exc:
            print(f"login({username!r}) -> IOException: {exc}")

    print(f"\n[+] Журнал подій збережено у {LOG_JSON}")
    print("=" * 80)


if __name__ == "__main__":
    main()
