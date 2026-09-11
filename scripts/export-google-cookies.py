#!/usr/bin/env python3
"""通过 CDP 从本机 Chrome 直接读出 Google 登录 cookie（含 HttpOnly），不需要手工导出。

为什么需要它：cookie 面板的多选复制容易漏项/截断，而磁盘上的 Chrome cookie 库是 `v11`
（AES-GCM），密钥存在系统钥匙串里，脚本没法自己解。CDP 让 **Chrome 自己**把明文 cookie 交出来，
于是既没有截断、也不会漏 HttpOnly 的 SID/HSID/SSID。

前置：Chrome 必须以调试端口启动（默认 9222）：

    # 先完全退出 Chrome（含托盘/后台），再执行：
    google-chrome --remote-debugging-port=9222 --user-data-dir="$HOME/.config/google-chrome"

用法：
  scripts/export-google-cookies.py                      # 只打印摘要（不显示 cookie 值）
  scripts/export-google-cookies.py --out data/gcookies.txt
  scripts/export-google-cookies.py --json --out data/gcookies.json
  scripts/export-google-cookies.py --show-values        # 明确要求时才把值打到终端

退出码：0 五个必需 cookie 齐了；1 有缺失或连不上 Chrome；2 参数/环境问题
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import stat
import sys
import urllib.request
from typing import Any, Dict, List

# 协议登录的必需集合（与 src/services/protocol_login.py 的 GOOGLE_COOKIE_NAMES 一致）
REQUIRED_NAMES = ("SID", "HSID", "SSID", "APISID", "SAPISID")
# 顺手一起带上：能在 AT 过期时帮 Google 自己刷新会话
OPTIONAL_NAMES = ("__Secure-1PSID", "__Secure-3PSID", "__Secure-1PSIDTS", "__Secure-3PSIDTS", "LSID")


def cdp_http_endpoint(host: str, port: int) -> str:
    return f"http://{host}:{port}/json/version"


def fetch_ws_url(host: str, port: int, timeout: float = 5.0) -> str:
    with urllib.request.urlopen(cdp_http_endpoint(host, port), timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    url = payload.get("webSocketDebuggerUrl")
    if not url:
        raise RuntimeError("CDP 未返回 webSocketDebuggerUrl")
    return url


def select_google_cookies(cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """挑出 .google.com 上的登录 cookie。纯函数，便于测试。"""
    wanted = set(REQUIRED_NAMES) | set(OPTIONAL_NAMES)
    picked: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for cookie in cookies:
        name = str(cookie.get("name") or "")
        domain = str(cookie.get("domain") or "")
        value = str(cookie.get("value") or "")
        if name not in wanted or not value:
            continue
        if not (domain == "google.com" or domain.endswith(".google.com")):
            continue
        key = (name, domain)
        if key in seen:
            continue
        seen.add(key)
        picked.append(cookie)
    return picked


async def get_all_cookies(ws_url: str) -> List[Dict[str, Any]]:
    import websockets

    async with websockets.connect(ws_url, max_size=None, open_timeout=10) as ws:
        await ws.send(json.dumps({"id": 1, "method": "Storage.getCookies"}))
        while True:
            message = json.loads(await ws.recv())
            if message.get("id") != 1:
                continue  # 忽略事件推送
            if "error" in message:
                raise RuntimeError(f"Storage.getCookies 失败: {message['error']}")
            return list((message.get("result") or {}).get("cookies") or [])


def to_header(cookies: List[Dict[str, Any]]) -> str:
    # 必需项在前，便于人眼核对；同名的取先出现的那条
    ordered: List[Dict[str, Any]] = []
    for name in REQUIRED_NAMES + OPTIONAL_NAMES:
        for cookie in cookies:
            if cookie.get("name") == name:
                ordered.append(cookie)
                break
    return "; ".join(f"{c['name']}={c['value']}" for c in ordered)


def write_private(path: str, content: str) -> None:
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600：里面是可直接登录的凭据


def main() -> int:
    parser = argparse.ArgumentParser(description="通过 CDP 读出 Chrome 里的 Google 登录 cookie")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9222)
    parser.add_argument("--out", help="写入文件（默认不写；建议 data/gcookies.txt）")
    parser.add_argument("--json", action="store_true", help="以 Cookie-Editor 风格的 JSON 写入")
    parser.add_argument("--show-values", action="store_true", help="把 cookie 值打印到终端（默认只打摘要）")
    parser.add_argument("--self-test", action="store_true", help="离线自检筛选逻辑")
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    try:
        ws_url = fetch_ws_url(args.host, args.port)
    except Exception as exc:
        print(f"连不上 Chrome 的调试端口 {args.host}:{args.port}（{exc}）\n")
        print("Chrome 只有在启动时带调试端口才可被读取，请：")
        print("  1) 完全退出 Chrome（确认后台没有残留进程）")
        print('  2) 运行：google-chrome --remote-debugging-port=9222 --user-data-dir="$HOME/.config/google-chrome"')
        print("  3) 在该窗口打开 https://accounts.google.com 确认是登录态，然后重跑本脚本")
        return 1

    cookies = select_google_cookies(asyncio.run(get_all_cookies(ws_url)))
    if not cookies:
        print("Chrome 里没有 .google.com 的登录 cookie —— 这个配置文件没登录 Google")
        return 1

    by_name = {c["name"]: c for c in cookies}
    print(f"从 Chrome 读到 {len(cookies)} 个 Google 登录 cookie：")
    for name in REQUIRED_NAMES + OPTIONAL_NAMES:
        cookie = by_name.get(name)
        if not cookie:
            print(f"  ✗ {name:20s} 缺失")
            continue
        print(f"  ✓ {name:20s} {cookie.get('domain'):14s} {len(str(cookie.get('value')))} 字符"
              f"{'  HttpOnly' if cookie.get('httpOnly') else ''}")

    missing = [name for name in REQUIRED_NAMES if name not in by_name]
    if missing:
        print(f"\n缺少必需项 {', '.join(missing)}：请在该 Chrome 里登录 accounts.google.com 后重试")
        return 1

    if args.show_values:
        print("\n" + to_header(cookies))

    if args.out:
        if args.json:
            payload = json.dumps(cookies, ensure_ascii=False, indent=2)
        else:
            payload = to_header(cookies)
        write_private(args.out, payload)
        print(f"\n已写入 {args.out}（权限 0600）。接着可以：")
        print(f"  scripts/check-google-cookies.py --cookie-file {args.out} --trace")
    return 0


def self_test() -> int:
    """离线自检：只挑 google.com 域、去重、按必需项排序。"""
    sample = [
        {"name": "SID", "value": "a", "domain": ".google.com"},
        {"name": "SID", "value": "a", "domain": ".google.com"},          # 重复
        {"name": "HSID", "value": "b", "domain": ".google.com"},
        {"name": "SSID", "value": "c", "domain": "google.com"},
        {"name": "NID", "value": "d", "domain": ".google.com"},          # 不需要
        {"name": "SID", "value": "e", "domain": ".youtube.com"},         # 域不对
        {"name": "APISID", "value": "", "domain": ".google.com"},        # 空值
        {"name": "SAPISID", "value": "f", "domain": ".google.com"},
    ]
    picked = select_google_cookies(sample)
    names = [c["name"] for c in picked]
    checks = [
        ("去重", names.count("SID") == 1),
        ("忽略无关 cookie", "NID" not in names),
        ("忽略非 google.com 域", "e" not in [c["value"] for c in picked]),
        ("忽略空值", "APISID" not in names),
        ("保留必需项", set(["SID", "HSID", "SSID", "SAPISID"]).issubset(set(names))),
        ("header 顺序以必需项开头", to_header(picked).startswith("SID=")),
    ]
    failed = 0
    for label, ok in checks:
        failed += 0 if ok else 1
        print(f"  {'PASS' if ok else 'FAIL'} {label}")
    print(f"self-test: {len(checks) - failed}/{len(checks)} 通过")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
