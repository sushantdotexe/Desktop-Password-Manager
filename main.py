"""
Desktop Password Manager – main entry point.

Usage:
    python main.py [--db PATH]

Options:
    --db PATH   Path to the vault database file.
                Defaults to ~/.password_manager/vault.db
"""

import argparse
from pathlib import Path

from src.gui import run_app


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Desktop Password Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--db",
        metavar="PATH",
        type=Path,
        default=None,
        help="Path to the vault database file (default: ~/.password_manager/vault.db)",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    run_app(db_path=args.db)


if __name__ == "__main__":
    main()
