"""Головний файл для демонстрації лабораторної роботи №1.

Варіант 10.
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[2]))

from labs.lab01.task1 import run_task1  # noqa: E402
from labs.lab01.task2 import run_task2  # noqa: E402
from labs.lab01.task3 import main as run_task3  # noqa: E402


def main() -> None:
    """Запускає всі три завдання послідовно."""
    run_task1()
    print("\n")
    run_task2()
    print("\n")
    run_task3()


if __name__ == "__main__":
    main()
