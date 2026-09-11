#!/usr/bin/env python3
"""按仓库自身的链路把某个 token 的 ST/AT 刷成新的。

走的就是线上那份代码：`TokenManager.resolve_session()`（ST 失效时用 Google cookie 协议登录换新 ST）
+ `TokenManager.update_token()`（落库，并顺带把因 429 被禁用的 token 恢复启用）。

用法：
  scripts/refresh-token.py --token-id 1 --dry-run          # 只看会改什么，不写库
  scripts/refresh-token.py --token-id 1                    # 用 data/gcookies.txt 刷新并落库
  scripts/refresh-token.py --token-id 1 --cookies-file data/gcookies.txt --proxy http://127.0.0.1:7890

cookie 文件优先级：--cookies-file > 库里该 token 已存的 google_cookies。
退出码：0 成功；1 失败（ST 仍不可用，且库未被修改）；2 参数/环境问题
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sqlite3
import sys
from datetime import datetime
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.database import Database  # noqa: E402
from src.services.flow_client import FlowClient  # noqa: E402
from src.services.token_manager import TokenManager  # noqa: E402

DEFAULT_COOKIE_FILE = "data/gcookies.txt"


def parse_expires(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def snapshot(db_path: str, token_id: int) -> dict:
    """只读快照，用于前后对照（不取 st/at 的值，避免把凭据打到终端）。"""
    with sqlite3.connect(db_path) as conn:
        row = conn.execute(
            "select is_active, protocol_mode, length(st), length(coalesce(at,'')) , "
            "length(coalesce(google_cookies,'')), at_expires, ban_reason from tokens where id = ?",
            (token_id,),
        ).fetchone()
    if not row:
        raise SystemExit(f"库里没有 id={token_id} 的 token")
    keys = ("is_active", "protocol_mode", "st_len", "at_len", "cookies_len", "at_expires", "ban_reason")
    return dict(zip(keys, row))


def describe(snap: dict) -> str:
    return (f"is_active={snap['is_active']} 协议模式={snap['protocol_mode']} "
            f"ST={snap['st_len']}字符 AT={snap['at_len']}字符 cookies={snap['cookies_len']}字符 "
            f"AT过期={snap['at_expires']} ban={snap['ban_reason']!r}")


async def run(args: argparse.Namespace) -> int:
    before = snapshot(args.db, args.token_id)
    print(f"刷新前: {describe(before)}")

    cookies = ""
    if args.cookies_file and os.path.exists(args.cookies_file):
        cookies = open(args.cookies_file, encoding="utf-8").read().strip()
        print(f"使用 cookie 文件 {args.cookies_file}（{len(cookies)} 字符）")
    if not cookies:
        print("没有可用的 Google cookie：请先生成 data/gcookies.txt（scripts/export-google-cookies.py）")
        return 2

    db = Database(args.db)
    token_manager = TokenManager(db, FlowClient(proxy_manager=None, db=db))
    token = await db.get_token(args.token_id)
    if not token:
        print(f"库里没有 id={args.token_id} 的 token")
        return 2

    try:
        result = await token_manager.resolve_session(
            token.st,
            google_cookies=cookies,
            proxy_url=args.proxy or token.proxy_url,
            email=token.email,
        )
    except Exception as exc:
        print(f"\n刷新失败（数据库未改动）: {exc}")
        return 1

    new_st = result["st"]
    at = result["access_token"]
    at_expires = parse_expires(result.get("expires"))
    print(f"\n刷新成功: ST {'已重新登录换新' if result.get('st_refreshed') else '原样可用'}"
          f"（{len(new_st)} 字符），AT {len(at)} 字符，到期 {at_expires}")
    if result.get("st_refreshed") and result.get("stale_reason"):
        print(f"  （触发重登的原因：{result['stale_reason']}）")
    print(f"  账号: {(result.get('user') or {}).get('email') or token.email}")

    if args.dry_run:
        print("\n--dry-run：不写库。去掉该参数即落库。")
        return 0

    await token_manager.update_token(
        token.id,
        st=new_st,
        at=at,
        at_expires=at_expires,
        google_cookies=cookies,
    )
    after = snapshot(args.db, args.token_id)
    print(f"\n刷新后: {describe(after)}")
    if not before["is_active"] and after["is_active"]:
        print("注意：因为更新了凭证，该 token 已被自动恢复为启用状态（update_token 的既有行为）。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="用 Google cookie 刷新某个 token 的 ST/AT（走仓库自身链路）")
    parser.add_argument("--token-id", type=int, required=True)
    parser.add_argument("--cookies-file", default=DEFAULT_COOKIE_FILE)
    parser.add_argument("--db", default="data/flow.db")
    parser.add_argument("--proxy", help="可选代理，覆盖 token 上已存的 proxy_url")
    parser.add_argument("--dry-run", action="store_true", help="只打印将要发生的变化，不写库")
    args = parser.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
