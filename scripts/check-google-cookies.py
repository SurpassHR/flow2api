#!/usr/bin/env python3
"""检查一份 Google cookie 能不能走通 protocol_login 的刷新链路（不写数据库）。

为什么需要它：`ProtocolLogin.login()` 只有成功/失败两态，失败时那句话（“Google 拒绝登录，
Cookies 可能已过期或被风控”）既不说卡在哪一跳，也不说缺哪些 cookie。而刷新一次要走
csrf → signin/google → accounts.google.com OAuth → callback 四跳，只有逐跳看才能定位。
本脚本直接调用**仓库里同一份代码**（`src.services.protocol_login`），保证结论与线上一致。

用法：
  scripts/check-google-cookies.py --cookies 'SID=...; HSID=...; SSID=...; APISID=...; SAPISID=...'
  scripts/check-google-cookies.py --cookie-file gcookie.txt     # JSON 导出或 name=value 都行
  scripts/check-google-cookies.py --from-db 1                   # 取库里该 token 已存的 google_cookies
  cat gcookie.txt | scripts/check-google-cookies.py --stdin
  scripts/check-google-cookies.py --self-test                   # 离线自检判决逻辑（不联网）

退出码：0 换到了新的 ST；1 Google 不认这份 cookie（需在浏览器里重新登录后再导出）；2 无法判定
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.services.protocol_login import (  # noqa: E402
    GOOGLE_COOKIE_NAMES,
    LABS_BASE,
    ProtocolLogin,
    _build_cookie_header,
    _parse_google_cookies,
)

LABS_ORIGIN = "https://labs.google"


def preflight(cookies: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """判断 cookie 集合是否够用。返回 (缺失的必要 cookie, 提示信息)。

    SID/HSID/SSID 是 Google 的完整性三元组：SID 是会话本体，HSID/SSID 是校验值。只发
    SID 时 Google 无法确认会话未被篡改，会当成“未登录”并把人送回 /v3/signin/identifier——
    这正是“cookie 看起来有，但刷新永远失败”的最常见原因，所以单独点名。
    """
    missing = [name for name in GOOGLE_COOKIE_NAMES if name not in cookies]
    hints: List[str] = []
    if "SID" not in cookies:
        hints.append("缺 SID：这是会话本体，没有它必然失败")
    integrity = [n for n in ("HSID", "SSID") if n not in cookies]
    if "SID" in cookies and integrity:
        hints.append(
            f"缺 {'/'.join(integrity)}：它们是 SID 的完整性校验值（HttpOnly，"
            "`document.cookie` 与请求头复制通常拿不到，必须在 DevTools → Application → Cookies 里导出）"
        )
    if not any(n.startswith("__Secure-") and n.endswith("PSID") for n in cookies):
        hints.append(
            "没有 __Secure-1PSID / __Secure-3PSID：正常登录态的 .google.com cookie 里通常成对存在，"
            "只有 APISID 对、没有 PSID 对，往往说明这份 cookie 是从已登出的会话里拷出来的"
        )
    return missing, hints


def read_from_db(token_id: int, db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("select google_cookies from tokens where id = ?", (token_id,)).fetchone()
    finally:
        conn.close()
    if not row:
        raise SystemExit(f"库里没有 id={token_id} 的 token")
    return row[0] or ""


async def trace(cookies: Dict[str, str], proxy: Optional[str]) -> None:
    """逐跳复现 OAuth 链路，指出卡在哪一步（只读，不碰数据库）。"""
    from curl_cffi.requests import AsyncSession

    kwargs: Dict[str, object] = {"impersonate": "chrome124", "trust_env": False}
    if proxy:
        kwargs["proxy"] = proxy
    cookie_header = _build_cookie_header(cookies)

    print("\n逐跳追踪：")
    async with AsyncSession(**kwargs) as session:
        try:
            r = await session.get(f"{LABS_BASE}/api/auth/csrf")
            token = (r.json() or {}).get("csrfToken") if r.status_code == 200 else None
            print(f"  hop0  GET  {LABS_BASE}/api/auth/csrf -> HTTP {r.status_code}")
            if not token:
                print("        没有 csrfToken，后面的跳没必要走了")
                return

            r = await session.post(
                f"{LABS_BASE}/api/auth/signin/google",
                data={"csrfToken": token, "callbackUrl": LABS_BASE, "json": "true"},
                headers={"Referer": LABS_BASE, "Origin": LABS_ORIGIN},
                allow_redirects=False,
            )
            data = r.json() or {}
            url = data.get("redirect") or data.get("url")
            print(f"  hop1  POST .../signin/google -> HTTP {r.status_code}，拿到 OAuth URL: {bool(url)}")
            if not url:
                return

            for i in range(4):
                r = await session.get(
                    url,
                    headers={"Cookie": cookie_header, "Referer": "https://accounts.google.com/"},
                    allow_redirects=False,
                )
                location = (r.headers.get("location") or "").strip()
                print(f"  hop{2 + i} GET  {url[:88]}")
                print(f"        -> HTTP {r.status_code} {location[:100]}")
                if not location:
                    body = r.text or ""
                    if "signin/rejected" in body.lower():
                        print("        页面含 signin/rejected：Google 不认这份 cookie 是已登录会话")
                    break
                if "callback/google" in location:
                    print("        ✅ 到达 labs.google 回调，cookie 有效")
                    break
                url = location if location.startswith("http") else "https://accounts.google.com" + location
                if "signin/identifier" in url:
                    print("        ⛔ Google 要求重新输入账号 = 这份 cookie 没有构成已登录会话")
                    break
        except Exception as exc:  # 网络/代理问题不应伪装成“cookie 无效”
            print(f"  追踪中断: {exc}")


async def check(cookies: Dict[str, str], proxy: Optional[str]) -> Tuple[int, str, Optional[str]]:
    """调用仓库的生产代码路径，返回 (退出码, 结论, 新 ST)。"""
    result = await ProtocolLogin().login(json.dumps(cookies, ensure_ascii=False), proxy=proxy)
    if result.get("success"):
        st = result.get("session_token") or ""
        return 0, f"✅ 换到新 ST（{len(st)} 字符，前缀 {st[:12]}…）", st
    error = str(result.get("error") or "未知错误")
    if "拒绝登录" in error or "session" in error.lower():
        return 1, f"❌ {error}", None
    return 2, f"⚠️ {error}", None


def main() -> int:
    parser = argparse.ArgumentParser(description="检查 Google cookie 能否刷新 ST（只读，不写库）")
    src = parser.add_mutually_exclusive_group(required=False)
    src.add_argument("--cookies", help="cookie 字符串（name=value; name=value 或 JSON 导出）")
    src.add_argument("--cookie-file", help="从文件读取 cookie")
    src.add_argument("--from-db", type=int, help="从 data/flow.db 读取该 token 已存的 google_cookies")
    src.add_argument("--stdin", action="store_true", help="从标准输入读取 cookie")
    src.add_argument("--self-test", action="store_true", help="离线自检判决逻辑，不联网")
    parser.add_argument("--proxy", help="可选代理，如 http://127.0.0.1:7890")
    parser.add_argument("--db", default="data/flow.db", help="数据库路径（配合 --from-db）")
    parser.add_argument("--trace", action="store_true", help="失败时逐跳追踪定位")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    raw = args.cookies or ""
    if args.cookie_file:
        raw = open(args.cookie_file, encoding="utf-8").read()
    elif args.from_db is not None:
        raw = read_from_db(args.from_db, args.db)
    elif args.stdin:
        raw = sys.stdin.read()

    cookies = _parse_google_cookies(raw)
    if not cookies:
        print("没有解析出任何 cookie（支持 JSON 导出或 name=value; name=value）")
        return 2

    print(f"解析到 {len(cookies)} 个 cookie: {', '.join(cookies)}")
    missing, hints = preflight(cookies)
    if missing:
        print(f"缺失（协议登录要求的最小集合 {GOOGLE_COOKIE_NAMES}）: {', '.join(missing)}")
    for hint in hints:
        print(f"  · {hint}")

    code, verdict, st = asyncio.run(check(cookies, args.proxy))
    print(f"\n用仓库同一份代码实测: {verdict}")
    if code != 0 and args.trace:
        asyncio.run(trace(cookies, args.proxy))
    if code != 0:
        print(
            "\n需要做的事：在浏览器里登出再登录 accounts.google.com，确认打开 "
            "https://accounts.google.com 能看到头像/账号（而不是登录表单），"
            "然后 DevTools → Application → Cookies → https://accounts.google.com 导出**全部**行"
            "（含 HttpOnly 的 SID/HSID/SSID 与 __Secure-*PSID）。仅重载页面或重新复制同一份 cookie 无效。"
        )
    return code


def self_test() -> int:
    """离线自检 preflight 的判决，避免“判据本身写错”这种低级错误。"""
    cases = [
        ({"SID": "a", "HSID": "b", "SSID": "c", "APISID": "d", "SAPISID": "e",
          "__Secure-1PSID": "f"}, [], []),
        ({"APISID": "d", "SAPISID": "e", "SID": "a"}, ["HSID", "SSID"], None),
        ({"HSID": "b", "SSID": "c"}, ["SID", "APISID", "SAPISID"], None),
    ]
    failed = 0
    for cookies, expect_missing, _ in cases:
        missing, _hints = preflight(cookies)
        ok = missing == expect_missing
        failed += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'} missing={missing}（期望 {expect_missing}）")
    print(f"self-test: {len(cases) - failed}/{len(cases)} 通过")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
