#!/usr/bin/env python3
"""CLI для proxy-parser-claude.

Команды:
    python main.py scrape                 — собрать прокси с proxyscrape.com в results/all_proxies.json
    python main.py check                  — проверить прокси из results/all_proxies.json, сохранить рабочие в results/working_proxies.json
    python main.py all                    — scrape + check одной командой
    python main.py serve [--port 1080]    — поднять локальный SOCKS5-роутер (без прав администратора)
    python main.py vpn-config             — сгенерировать vpn/config.json для sing-box (системный VPN через TUN)
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from proxyparser import (app_routing, scraper, checker, filters, pipeline, storage, local_router, singbox_config,
                         singbox_manager)
from proxyparser.reputation import Reputation  # noqa: E402

log = logging.getLogger("proxyparser")

VPN_CONFIG_PATH = singbox_manager.CONFIG_PATH


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_scrape(args: argparse.Namespace) -> None:
    proxies, stats = scraper.scrape()
    storage.save_scraped(proxies)
    log.info("Собрано %d уникальных прокси (%s). Сохранено в %s", stats.proxies_found,
             ", ".join(f"{k}: {v}" for k, v in stats.per_source.items()), storage.ALL_PROXIES_FILE)
    for name, err in stats.sources_failed.items():
        log.warning("Источник %s не открылся: %s", name, err)
    by_type: dict[str, int] = {}
    for p in proxies:
        by_type[p.type.value] = by_type.get(p.type.value, 0) + 1
    for t, n in sorted(by_type.items()):
        log.info("  %s: %d", t, n)


def cmd_check(args: argparse.Namespace) -> None:
    proxies = storage.load_scraped()
    if not proxies:
        log.error("results/all_proxies.json пуст или не найден — сначала запустите `scrape`")
        sys.exit(1)

    last = {"stage": None}

    def on_stage(name: str, done: int, total: int) -> None:
        if name != last["stage"] or done == total:
            log.info("%s: %d/%d", name, done, total)
            last["stage"] = name

    rep = Reputation.load()
    results, stats = asyncio.run(pipeline.run(proxies, rep, concurrency=args.concurrency, timeout=args.timeout, on_stage=on_stage))
    rep.save()
    storage.save_results(results)
    if stats.skipped_farms:
        log.info("Не проверялись лишние порты «ферм»: %d", stats.skipped_farms)

    working = [r for r in results if r.working]
    excluded = sum(1 for r in results if r.error == filters.EXCLUDE_REASON)
    if excluded:
        log.info("Исключено прокси из России: %d", excluded)
    log.info("Готово: рабочих %d из %d (%.1f%%). Сохранено в %s", len(working), len(results), 100 * len(working) / max(len(results), 1), storage.WORKING_PROXIES_FILE)
    by_type: dict[str, int] = {}
    for r in working:
        by_type[r.proxy.type.value] = by_type.get(r.proxy.type.value, 0) + 1
    for t, n in sorted(by_type.items()):
        log.info("  %s: %d рабочих", t, n)


def cmd_all(args: argparse.Namespace) -> None:
    cmd_scrape(args)
    cmd_check(args)


def cmd_serve(args: argparse.Namespace) -> None:
    results = storage.load_working_proxies()
    if not results:
        log.error("Нет рабочих прокси в results/working_proxies.json — сначала запустите `all` (или `scrape` + `check`)")
        sys.exit(1)
    log.info("Запускаю локальный SOCKS5-роутер. Пропиши в браузере/приложении прокси SOCKS5 127.0.0.1:%d", args.port)
    try:
        asyncio.run(local_router.serve(results, host=args.host, port=args.port))
    except KeyboardInterrupt:
        log.info("Остановлено пользователем")


def cmd_vpn_config(args: argparse.Namespace) -> None:
    results = storage.load_working_proxies()
    if not results:
        log.error("Нет рабочих прокси в results/working_proxies.json — сначала запустите `all` (или `scrape` + `check`)")
        sys.exit(1)
    try:
        meta = singbox_config.write_config(results, VPN_CONFIG_PATH,
                                           bypass_process_paths=singbox_manager.own_process_paths(),
                                           routing=app_routing.load())
    except ValueError as exc:
        log.error(str(exc))
        sys.exit(1)
    log.info("Конфиг sing-box записан в %s", VPN_CONFIG_PATH)
    log.info(meta["comment_ru"])
    log.info("Дальше: vpn/setup_vpn.ps1 один раз (от администратора), затем vpn/start_vpn.ps1 для включения VPN")


def main() -> None:
    parser = argparse.ArgumentParser(description="proxy-parser-claude")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scrape = sub.add_parser("scrape", help="собрать прокси с proxyscrape.com")
    p_scrape.set_defaults(func=cmd_scrape)

    p_check = sub.add_parser("check", help="проверить собранные прокси на рабочесть")
    p_check.add_argument("--concurrency", type=int, default=checker.DEFAULT_CONCURRENCY)
    p_check.add_argument("--timeout", type=float, default=checker.DEFAULT_TIMEOUT_S)
    p_check.set_defaults(func=cmd_check)

    p_all = sub.add_parser("all", help="scrape + check одной командой")
    p_all.add_argument("--concurrency", type=int, default=checker.DEFAULT_CONCURRENCY)
    p_all.add_argument("--timeout", type=float, default=checker.DEFAULT_TIMEOUT_S)
    p_all.set_defaults(func=cmd_all)

    p_serve = sub.add_parser("serve", help="локальный SOCKS5-роутер (без прав администратора)")
    p_serve.add_argument("--host", default=local_router.DEFAULT_LISTEN_HOST)
    p_serve.add_argument("--port", type=int, default=local_router.DEFAULT_LISTEN_PORT)
    p_serve.set_defaults(func=cmd_serve)

    p_vpn = sub.add_parser("vpn-config", help="сгенерировать конфиг sing-box для системного VPN (TUN)")
    p_vpn.set_defaults(func=cmd_vpn_config)

    args = parser.parse_args()
    _setup_logging(args.verbose)
    args.func(args)


if __name__ == "__main__":
    main()
