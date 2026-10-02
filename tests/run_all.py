"""Запустить все тесты по очереди: python tests\\run_all.py"""
import os
import pathlib
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
# Вывод тестов перехватывается через канал, а там у Python на русской Windows
# кодировка cp1251 — символы вроде «→» в ней не пишутся, и тест падал на print.
CHILD_ENV = {**os.environ, "PYTHONIOENCODING": "utf-8"}


def main() -> int:
    sys.stdout.reconfigure(errors="replace")  # и сам вывод сводки не падает на таких символах
    failed = []
    for test in sorted(HERE.glob("test_*.py")):
        start = time.monotonic()
        proc = subprocess.run([sys.executable, str(test)], capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=300, env=CHILD_ENV)
        ok = proc.returncode == 0
        print(f"{'OK  ' if ok else 'FAIL'} {test.name:28} {time.monotonic() - start:5.1f} с")
        if not ok:
            failed.append(test.name)
            print(proc.stdout[-2000:], proc.stderr[-3000:], sep="\n")
    print("\nВсе тесты прошли." if not failed else f"\nУпали: {', '.join(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
