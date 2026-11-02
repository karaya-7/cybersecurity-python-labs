"""Точка входу ЛР №2: python -m labs.lab02.main demo|analyze."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC

from . import task1, task2


def _demo() -> int:
    print("=== Демонстрація ООП (Завдання 1) ===")
    admin = task1.Admin("alice", "alice@example.com", permissions=["read"])
    admin.set_password("S3cret!")

    account = task1.UserAccount(user=admin)
    print(f"1. Успішний вхід: {account.login('alice', 'S3cret!', '10.0.0.5')}")
    print(f"   is_authenticated: {account.is_authenticated()}")

    print(f"2. Невдалий вхід: {account.login('alice', 'wrong', '10.0.0.5')}")

    try:
        admin.email = "not-an-email"
    except ValueError as exc:
        print(f"3. Валідація email: {exc}")
    admin.email = "new.alice@example.org"
    print(f"   Новий email: {admin.email}")

    admin.grant_permission("write")
    print(f"4. Admin: {admin}")
    print(f"   has_permission('write'): {admin.has_permission('write')}")
    admin.revoke_permission("write")
    print(
        f"   has_permission('write') після revoke: {admin.has_permission('write')}"
    )

    # Імітація таймауту
    if account["session"] is not None:
        from datetime import datetime, timedelta

        account["session"].last_activity = datetime.now(UTC) - timedelta(
            seconds=task1.SESSION_TIMEOUT_SEC + 1
        )
    print(f"5. Після таймауту is_authenticated: {account.is_authenticated()}")

    account.logout()
    print("6. Після logout сесія:", account["session"])
    print("7. AuditLog:")
    for rec in account["audit_log"].show_all():
        print(
            f"   {rec.timestamp.isoformat()} | {rec.username} | {rec.action}"
        )
    return 0


def _analyze(argv: list[str]) -> int:
    return task2.main(argv)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="labs.lab02.main")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Демонстрація ООП (Завдання 1)")

    analyze = sub.add_parser(
        "analyze", help="Аналіз SSL-сертифікатів (Варіант 10)"
    )
    analyze.add_argument("--certs-data", required=True)
    analyze.add_argument("--days-warning", type=int, default=30)
    analyze.add_argument("--output-report", default="ssl_expiry_report.csv")
    analyze.add_argument("--format", choices=["csv", "json"], default="csv")
    analyze.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "demo":
        return _demo()
    if args.command == "analyze":
        # Передаємо рештки в task2
        rest = [
            "--certs-data",
            args.certs_data,
            "--days-warning",
            str(args.days_warning),
            "--output-report",
            args.output_report,
            "--format",
            args.format,
            "--log-level",
            args.log_level,
        ]
        return _analyze(rest)
    return 1


if __name__ == "__main__":
    sys.exit(main())
