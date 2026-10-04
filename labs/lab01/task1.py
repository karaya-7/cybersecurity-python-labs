"""Завдання 1: Комплексний аналізатор надійності паролів.

Варіант 10.
"""

import random
import sys
from pathlib import Path

# Додаємо корінь репозиторію до sys.path
sys.path.append(str(Path(__file__).resolve().parents[2]))

from shared.student import (  # noqa: E402
    GROUP_NAME,
    STUDENT_NAME,
    VARIANT_NUMBER,
)

# --- Вхідні дані для варіанту 10 ---
PASSWORDS = [
    "S0cial@Engineer",
    "basic",
    "Phish1ng@D3tect",
    "client",
    "Ransomwar3@Protect",
    "general",
    "Zero@D4y",
    "generic",
    "Bug@B0unty",
    "standard123",
]

CRITERIA = {
    "min_length": 11,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "basic",
    "client",
    "general",
    "generic",
    "standard123",
    "guest",
}

SPECIAL_CHARS = set("!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~")


def has_digit(password: str) -> bool:
    """Перевіряє наявність хоча б однієї цифри."""
    return any(ch.isdigit() for ch in password)


def has_upper(password: str) -> bool:
    """Перевіряє наявність хоча б однієї великої літери."""
    return any(ch.isupper() for ch in password)


def has_lower(password: str) -> bool:
    """Перевіряє наявність хоча б однієї малої літери."""
    return any(ch.islower() for ch in password)


def has_special(password: str) -> bool:
    """Перевіряє наявність хоча б одного спеціального символу."""
    return any(ch in SPECIAL_CHARS for ch in password)


def evaluate_password(password: str, all_passwords: list[str]) -> str:
    """Оцінює надійність пароля.

    Повертає одну з категорій:
    'Заборонений', 'Слабкий', 'Середній', 'Сильний', 'Дуже сильний'.
    """
    min_length = CRITERIA["min_length"]

    # 1. Заборонений
    if password.lower() in FORBIDDEN_PASSWORDS or len(password) < min_length:
        return "Заборонений"

    checks = {
        "digit": has_digit(password),
        "upper": has_upper(password),
        "lower": has_lower(password),
        "special": has_special(password),
    }

    passed = sum(checks.values())

    # 2. Слабкий — виконує хоча б один, але не всі критерії
    if passed <= 2:
        return "Слабкий"

    # 3. Середній — деякі, але не всі критерії
    if passed < 4:
        return "Середній"

    # Далі passed == 4 (усі критерії виконано)
    # 4. Сильний — всі критерії, довжина < min_length + 4
    if len(password) < min_length + 4:
        return "Сильний"

    # 5. Дуже сильний — всі критерії, довжина >= min_length + 4,
    #    і пароль унікальний у всьому списку
    if all_passwords.count(password) == 1:
        return "Дуже сильний"

    # якщо довгий, але дублюється — знижуємо до "Сильний"
    return "Сильний"


def run_task1() -> None:
    """Точка входу для завдання 1."""
    print("=" * 70)
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | "
        f"Варіант: {VARIANT_NUMBER}"
    )
    print("Завдання 1: Аналізатор надійності паролів")
    print("=" * 70)

    # Дублюємо 3 випадкові паролі (імітація повторного використання)
    random.seed(VARIANT_NUMBER)
    indices = random.sample(range(len(PASSWORDS)), 3)
    duplicated = [PASSWORDS[i] for i in indices]
    all_passwords = PASSWORDS + duplicated

    print(f"Додано дублікати паролів з індексами: {indices}")
    print(f"Дублікати: {duplicated}\n")

    # Заголовок таблиці
    print(f"{'№':<4}{'Пароль':<25}{'Довжина':<9}{'Оцінка':<16}")
    print("-" * 70)

    for idx, password in enumerate(all_passwords, start=1):
        mark = evaluate_password(password, all_passwords)
        print(f"{idx:<4}{password:<25}{len(password):<9}{mark:<16}")

    print("=" * 70)


if __name__ == "__main__":
    run_task1()
