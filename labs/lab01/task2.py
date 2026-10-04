"""Завдання 2: Багаторівнева система контролю доступу.

Варіант 10.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from shared.student import (  # noqa: E402
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

# --- Вхідні дані для варіанту 10 ---
USERS = {
    "iot_specialist": {
        "role": "iot_security",
        "clearance": 3,
        "department": "IoT",
        "active": True,
    },
    "mobile_analyst": {
        "role": "mobile_security",
        "clearance": 3,
        "department": "Mobile",
        "active": True,
    },
    "web_developer": {
        "role": "web_developer",
        "clearance": 2,
        "department": "Web",
        "active": True,
    },
    "api_consumer": {
        "role": "api_user",
        "clearance": 2,
        "department": "Integration",
        "active": True,
    },
    "demo_account": {
        "role": "demonstration",
        "clearance": 1,
        "department": "Demo",
        "active": False,
    },
}

RESOURCES = [
    ("iot_firmware", 3),
    ("mobile_policies", 3),
    ("web_applications", 2),
    ("api_gateway", 2),
    ("device_certificates", 3),
    ("app_store", 1),
    ("vulnerability_database", 3),
    ("device_management", 3),
    ("integration_docs", 2),
    ("demo_content", 1),
]

SECURITY_LEVELS = (
    "Consumer",
    "Business",
    "Enterprise",
    "Critical Systems",
)

BLOCKED_USERS = {"demo_account", "compromised_device", "malicious_app"}


def level_name(level: int) -> str:
    """Повертає текстову назву рівня безпеки за його номером (1..4)."""
    if 1 <= level <= len(SECURITY_LEVELS):
        return SECURITY_LEVELS[level - 1]
    return f"Unknown({level})"


def check_access(username: str, resource_level: int) -> tuple[bool, str]:
    """Перевіряє доступ користувача до ресурсу.

    Повертає (True, "") якщо доступ дозволено,
    або (False, "причина") якщо відмовлено.
    """
    # 1. Користувача немає в системі
    if username not in USERS:
        return False, "User not found"

    # 2. Заблокований
    if username in BLOCKED_USERS:
        return False, "User is blocked"

    user = USERS[username]

    # 3. Неактивний акаунт
    if not user["active"]:
        return False, "Account inactive"

    # 4. Рівень допуску достатній
    if user["clearance"] >= resource_level:
        return True, ""

    # 5. Недостатній рівень допуску
    return False, "Insufficient clearance"


def run_task2() -> None:
    """Точка входу для завдання 2."""
    print("=" * 80)
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | "
        f"Варіант: {VARIANT_NUMBER}"
    )
    print("Завдання 2: Багаторівнева система контролю доступу")
    print("=" * 80)

    # Виводимо список ресурсів з текстовими назвами рівнів безпеки
    print("\nДоступні ресурси системи:")
    print(f"{'Ресурс':<25}{'Рівень':<20}")
    print("-" * 50)
    for name, level in RESOURCES:
        print(f"{name:<25}{level_name(level):<20}")

    # Перевіряємо доступ для всіх користувачів до всіх ресурсів
    test_users = list(USERS.keys()) + ["unknown_user", "compromised_device"]

    print("\nРезультати перевірки доступу:")
    print("-" * 80)
    for user in test_users:
        for resource_name, resource_level in RESOURCES:
            allowed, reason = check_access(user, resource_level)
            if allowed:
                verdict = "ALLOW"
                tail = ""
            else:
                verdict = "DENY"
                tail = f" ({reason})"
            print(
                f"user={user} resource={resource_name} -> " f"{verdict}{tail}"
            )
    print("=" * 80)


if __name__ == "__main__":
    run_task2()
