"""Завдання 2 (Варіант 10): Монітор термінів дії SSL/TLS сертифікатів."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

LOG = logging.getLogger("ssl_monitor")

_WEAK_ALGS = re.compile(r"(sha1|md5)", re.IGNORECASE)


@dataclass
class CertReport:
    domain: str
    issuer: str
    valid_to: datetime
    days_left: int
    status: str  # OK / WARNING / EXPIRED / WEAK
    signature_algorithm: str
    key_length: int


def _parse_date(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d")


def load_certs(path: Path) -> list[dict]:
    if not path.is_file():
        raise FileNotFoundError(f"Файл сертифікатів не знайдено: {path}")
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("Очікується список сертифікатів у JSON")
    return data


def analyse(certs: list[dict], days_warning: int) -> list[CertReport]:
    now = datetime.now()
    reports: list[CertReport] = []
    for cert in certs:
        try:
            domain = str(cert["domain"])
            issuer = str(cert.get("issuer", "Unknown"))
            valid_to = _parse_date(cert["validTo"])
            alg = str(cert.get("signatureAlgorithm", ""))
            key_len = int(cert.get("keyLength", 0))
        except (KeyError, TypeError, ValueError) as exc:
            LOG.warning("Пропущено некоректний сертифікат: %s (%s)", cert, exc)
            continue

        days_left = (valid_to - now).days
        if days_left < 0:
            status = "EXPIRED"
        elif _WEAK_ALGS.search(alg) or key_len and key_len < 2048:
            status = "WEAK"
        elif days_left <= days_warning:
            status = "WARNING"
        else:
            status = "OK"

        reports.append(
            CertReport(
                domain=domain,
                issuer=issuer,
                valid_to=valid_to,
                days_left=days_left,
                status=status,
                signature_algorithm=alg,
                key_length=key_len,
            )
        )
    return reports


def _save_csv(reports: list[CertReport], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "domain",
                "issuer",
                "valid_to",
                "days_left",
                "status",
                "signature_algorithm",
                "key_length",
            ]
        )
        for r in reports:
            writer.writerow(
                [
                    r.domain,
                    r.issuer,
                    r.valid_to.date().isoformat(),
                    r.days_left,
                    r.status,
                    r.signature_algorithm,
                    r.key_length,
                ]
            )


def _save_json(reports: list[CertReport], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "domain": r.domain,
            "issuer": r.issuer,
            "valid_to": r.valid_to.date().isoformat(),
            "days_left": r.days_left,
            "status": r.status,
            "signature_algorithm": r.signature_algorithm,
            "key_length": r.key_length,
        }
        for r in reports
    ]
    with output.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def run(args: argparse.Namespace) -> int:
    logging.basicConfig(
        level=args.log_level,
        format="[%(levelname)s] %(message)s",
        stream=sys.stderr,
    )
    certs_path = Path(args.certs_data)
    LOG.info("Loading SSL certificates data from %s...", certs_path)
    try:
        certs = load_certs(certs_path)
    except (OSError, ValueError) as exc:
        LOG.error("Не вдалося прочитати сертифікати: %s", exc)
        return 1

    LOG.info("Audited %d domain certificates.", len(certs))
    reports = analyse(certs, args.days_warning)

    # Таблиця
    print("\n=== Certificate Expiry & Safety Status ===")
    print(
        f"{'Domain':32} {'Issuer':18} {'Days Left':>10} {'Status':10} Signature Alg"
    )
    for r in sorted(reports, key=lambda x: x.days_left):
        print(
            f"{r.domain:32} {r.issuer:18} {r.days_left:>10} {r.status:10} {r.signature_algorithm}"
        )

    # Статистика за видавцем
    print("\n=== Issuer Statistics ===")
    for issuer, count in Counter(r.issuer for r in reports).most_common():
        print(f"{issuer:20}: {count}")

    # Попередження
    expired = sum(1 for r in reports if r.status == "EXPIRED")
    warning = sum(1 for r in reports if r.status == "WARNING")
    weak = sum(1 for r in reports if r.status == "WEAK")
    if expired:
        LOG.warning("%d certificate(s) EXPIRED!", expired)
    if warning:
        LOG.warning(
            "%d certificate(s) expiring within %d days!",
            warning,
            args.days_warning,
        )
    if weak:
        LOG.warning("%d certificate(s) use WEAK algorithms/keys!", weak)

    # Експорт
    output = Path(args.output_report)
    if args.format == "json":
        _save_json(reports, output)
    else:
        _save_csv(reports, output)
    LOG.info("Report saved to %s", output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Монітор термінів дії SSL/TLS сертифікатів (Варіант 10)"
    )
    p.add_argument(
        "--certs-data", required=True, help="Шлях до JSON з сертифікатами"
    )
    p.add_argument(
        "--days-warning",
        type=int,
        default=30,
        help="Поріг днів для попередження (за замовч. 30)",
    )
    p.add_argument(
        "--output-report",
        default="ssl_expiry_report.csv",
        help="Шлях до файлу звіту",
    )
    p.add_argument(
        "--format",
        choices=["csv", "json"],
        default="csv",
        help="Формат звіту (csv або json)",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Exception as exc:  # noqa: BLE001
        logging.error("Непередбачена помилка: %s", exc)
        return 2
