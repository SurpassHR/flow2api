"""Google Cookies 凭证健康检查。

背景
----
``token.google_cookies``(Google 账号态 cookie:SID/HSID/SSID/APISID/SAPISID 等)
一旦失效,会立刻产生一连串互相矛盾的假象,极易把排查带偏:

- 插件仍能推送 labs.google 的 session-token,``ST→AT`` 甚至还能返回用户信息;
- 打码浏览器却打不开 flow.google.com 的登录态应用页(被 302 到 accounts.google.com);
- 协议模式刷新 ST 只报“Google 拒绝登录”,看不出根因其实是 cookies 已死;
- 上游提交返回 401/403(PUBLIC_ERROR_UNUSUAL_ACTIVITY),看起来像打码或 token 签发源的问题。

本模块用一个轻量 HTTP 探针给 google_cookies 一个明确结论
(``valid`` / ``invalid`` / ``incomplete`` / ``missing`` / ``unknown``),
附带 TTL 缓存、后台巡检和“由可用变失效”时的一次性告警日志,管理台可直接展示。
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

from curl_cffi.requests import AsyncSession

from ..core.config import config
from ..core.logger import debug_logger
from .browser_cookie_utils import serialize_cookie_header
from .protocol_login import GOOGLE_COOKIE_NAMES, _normalize_proxy_url

# 探测入口用 accounts.google.com 而不是 myaccount.google.com(2026-09-11 实测):
# 协议登录(protocol_login)走的就是 accounts.google.com 的 OAuth 入口,而
# myaccount.google.com 对同一组**能跑通协议登录**的 Cookie 会报未登录
# (它要求单一世代的会话 Cookie:明文 SID 与 __Secure-*PSID 同时出现就判未登录,
# 还会因为缺 __Secure-STRP/AEC 这类账号态 Cookie 而要求重新验证)。
# 用 myaccount 当唯一探测器会把好 Cookie 报成“已失效”,把人带去查错方向。
DEFAULT_PROBE_URL = "https://accounts.google.com/"
# 最多跟随几跳重定向:被动 SSO 的典型路径是
# myaccount → ServiceLogin?passive=1209600 → 再跳回 myaccount。
MAX_PROBE_HOPS = 4
IMPERSONATE = "chrome124"

STATUS_VALID = "valid"
STATUS_INVALID = "invalid"
STATUS_INCOMPLETE = "incomplete"
STATUS_MISSING = "missing"
STATUS_UNKNOWN = "unknown"
STATUS_CHECKING = "checking"
STATUS_UNCHECKED = "unchecked"

STATUS_LABELS: Dict[str, str] = {
    STATUS_VALID: "Cookie 有效",
    STATUS_INVALID: "Cookie 已失效",
    STATUS_INCOMPLETE: "Cookie 不完整",
    STATUS_MISSING: "未配置 Cookie",
    STATUS_UNKNOWN: "Cookie 状态未知",
    STATUS_CHECKING: "正在检查 Cookie",
    STATUS_UNCHECKED: "Cookie 未检查",
}

# 需要告警的状态(只有这些状态会在管理台和日志里明确提示)
PROBLEM_STATUSES = (STATUS_INVALID, STATUS_INCOMPLETE)
# 依赖 google_cookies 的凭证,缺失时同样算异常
MISSING_WORTH_WARNING_MODES = ("protocol",)

# 判定"这是一个登录/重新认证页面"的特征。
# 特意**不**包含裸的 "accounts.google.com":该域本身也是 OAuth 入口
# (accounts.google.com/o/oauth2/...),把它当成登录页会让正常会话被误判;只看路径特征。
LOGIN_HINTS = ("servicelogin", "/signin", "signin/v2", "signin/identifier", "identifiernext")


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status or STATUS_UNKNOWN)


def _result(
    status: str,
    detail: str,
    *,
    http_status: Optional[int] = None,
    location: str = "",
    cookie_names: Optional[List[str]] = None,
    error: str = "",
) -> Dict[str, Any]:
    return {
        "status": status,
        "detail": detail,
        "http_status": http_status,
        "location": location,
        "cookie_names": cookie_names or [],
        "error": error,
    }


def _field(source: Any, name: str, default: Any = "") -> Any:
    """兼容 sqlite3.Row / dict / 数据类三种入参形态地取字段。"""
    if source is None:
        return default
    if hasattr(source, "keys"):
        try:
            return source[name]
        except Exception:
            pass
    return getattr(source, name, default)


def _parse_cookie_pairs(cookie_header: str) -> Dict[str, str]:
    pairs: Dict[str, str] = {}
    for chunk in (cookie_header or "").split(";"):
        segment = chunk.strip()
        if not segment or "=" not in segment:
            continue
        name, _, value = segment.partition("=")
        name = name.strip()
        if name:
            pairs[name] = value.strip()
    return pairs


def build_google_cookie_header(raw_cookie: Any) -> str:
    """把 ``token.google_cookies``(JSON 导出或 name=value 文本)转成 Cookie 请求头。"""
    header = serialize_cookie_header(raw_cookie)
    if header:
        return header
    return str(raw_cookie or "").strip()


# 导出不全时最容易漏、也是 Google 判定账号态真正依赖的那几项(2026-09-11 实测):
# 一组只带 SID/HSID/SSID/APISID/SAPISID(老名字)的 Cookie,浏览器里明明是登录态,
# 纯 HTTP 请求却会被判未登录;补上 __Secure-*PSIDTS(会话轮转)与 OSID 后就正常。
#
# 注意这里**只是提示文案**,不参与判定(判定以真实探测为准),所以宁可少写:
# - SID/HSID/APISID/LSID 不在内 —— 实测一组完全没有它们的 Cookie 依然有效;
# - __Secure-STRP 也不在内 —— 实测缺它的 Cookie 照样能跑通协议登录。
# 名单写多了会把"有效"错报成"不完整",反而更容易把人带错方向。
CRITICAL_COOKIE_NAMES = (
    "SSID",
    "SAPISID",
    "__Secure-1PSIDTS",
    "__Secure-3PSIDTS",
    "OSID",
)


def _missing_critical_hint(pairs: Dict[str, str]) -> str:
    missing = [name for name in CRITICAL_COOKIE_NAMES if name not in pairs]
    if not missing:
        return ""
    return (
        "；同时发现缺少会话轮转/账号态 Cookie "
        + "/".join(missing)
        + "(常见于只导出 SID/HSID 这类老名字,建议在管理台“立即提取凭证”重采一次全量)"
    )


def _looks_like_login_redirect(location: str) -> bool:
    lowered = (location or "").lower()
    return any(hint in lowered for hint in LOGIN_HINTS)


def _looks_like_login_page(body: str) -> bool:
    lowered = (body or "")[:6000].lower()
    if "servicelogin" in lowered or "identifiernext" in lowered:
        return True
    return "gaia" in lowered and ("signin" in lowered or "sign in" in lowered)


def _looks_like_challenge_page(url: str) -> bool:
    """验证/风控/授权同意页:既不能算有效,也不能算 Cookie 失效。"""
    lowered = (url or "").lower()
    return "/sorry/" in lowered or "consent.google.com" in lowered or "/consent" in lowered


async def probe_google_cookies(
    cookie_header: str,
    *,
    probe_url: Optional[str] = None,
    proxy_url: Optional[str] = None,
    timeout_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """探测一组 Google Cookies 是否仍处于登录态。

    判定方式(跟随重定向,最多 ``MAX_PROBE_HOPS`` 跳,以最终落点为准):
    - 被送到 google.com / myaccount.google.com 的登录态页面 → 有效;
    - 最终停(or 连续两跳都在)``accounts.google.com/ServiceLogin`` / ``/signin``
      → 已失效;
    - 200 但页面是登录页 → 已失效;
    - 其余情况(网络错误等) → 未知,绝不误报失效。

    为什么必须跟随重定向(2026-09-11 实测):Google 的被动 SSO 会先把请求
    302 到 ``accounts.google.com/ServiceLogin?passive=1209600&continue=...``,
    会话**仍然有效**时它再 302 回原页面。只看第一跳就判“失效”会错杀 ——
    一组实测能跑通协议登录(换到 ST 1083 字符)的 Cookie 就是这样被报成失效的,
    于是 token 被标红、协议模式被误关,排查方向也全跑偏。
    """
    url = (probe_url or config.google_cookie_health_probe_url or DEFAULT_PROBE_URL).strip()
    header = (cookie_header or "").strip()
    pairs = _parse_cookie_pairs(header)
    if not header or not pairs:
        return _result(STATUS_MISSING, "未配置 Google Cookies")

    present = [name for name in GOOGLE_COOKIE_NAMES if name in pairs]
    if not present:
        return _result(
            STATUS_INCOMPLETE,
            "缺少 SID/HSID/SSID/APISID/SAPISID,无法用于 Google 登录",
            cookie_names=list(pairs.keys()),
        )

    try:
        timeout_value = float(
            timeout_seconds
            if timeout_seconds is not None
            else config.google_cookie_health_check_timeout_seconds
        )
    except Exception:
        timeout_value = 12.0

    session_kwargs: Dict[str, Any] = {"impersonate": IMPERSONATE, "trust_env": False}
    normalized_proxy = _normalize_proxy_url(proxy_url)
    if normalized_proxy:
        session_kwargs["proxy"] = normalized_proxy

    status_code = 0
    location = ""
    body = ""
    hops: List[str] = []
    current_url = url
    login_seen = False
    try:
        async with AsyncSession(**session_kwargs) as session:
            for _ in range(MAX_PROBE_HOPS):
                response = await session.get(
                    current_url,
                    headers={
                        "Cookie": header,
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.9",
                    },
                    allow_redirects=False,
                    timeout=timeout_value,
                )
                status_code = int(getattr(response, "status_code", 0) or 0)
                location = str(
                    (getattr(response, "headers", {}) or {}).get("location")
                    or (getattr(response, "headers", {}) or {}).get("Location")
                    or ""
                ).strip()
                hops.append(f"{status_code} {current_url[:70]}")

                if status_code not in (301, 302, 303, 307, 308) or not location:
                    body = (getattr(response, "text", "") or "") if status_code == 200 else ""
                    break

                next_url = urljoin(current_url, location)
                if _looks_like_login_redirect(next_url):
                    if login_seen:
                        # 连续两跳都在登录页:被动 SSO 没有把会话放回来 → 确实失效
                        return _result(
                            STATUS_INVALID,
                            f"Google 要求重新登录({' → '.join(hops[-2:])})"
                            + _missing_critical_hint(pairs),
                            http_status=status_code,
                            location=next_url,
                            cookie_names=list(pairs.keys()),
                        )
                    # 第一次进登录页可能只是被动 SSO:跟过去看它会不会回弹
                    login_seen = True
                    current_url = next_url
                    continue

                if _looks_like_challenge_page(next_url):
                    return _result(
                        STATUS_UNKNOWN,
                        f"Google 返回了验证/风控页面({next_url[:140]}),无法判定 Cookie 状态",
                        http_status=status_code,
                        location=next_url,
                        cookie_names=list(pairs.keys()),
                    )

                # 目标不是登录页 → 会话被接受(Chrome 的被动 SSO 正是这样回弹的)
                return _result(
                    STATUS_VALID,
                    f"Cookie 有效({status_code} → {next_url[:180]})",
                    http_status=status_code,
                    location=next_url,
                    cookie_names=list(pairs.keys()),
                )
    except Exception as exc:  # 网络/代理问题不应被判成 Cookie 失效
        return _result(
            STATUS_UNKNOWN,
            f"探测请求失败: {exc}",
            cookie_names=list(pairs.keys()),
            error=str(exc),
        )

    hop_text = " → ".join(hops[-2:]) if hops else ""
    if status_code == 200:
        if _looks_like_login_page(body) or _looks_like_login_redirect(current_url):
            return _result(
                STATUS_INVALID,
                f"Google 返回了登录页({hop_text}),Cookie 已失效" + _missing_critical_hint(pairs),
                http_status=status_code,
                location=current_url,
                cookie_names=list(pairs.keys()),
            )
        return _result(
            STATUS_VALID,
            f"Google 会话有效({hop_text or 'HTTP 200'})",
            http_status=status_code,
            location=current_url,
            cookie_names=list(pairs.keys()),
        )

    if status_code in (401, 403):
        return _result(
            STATUS_INVALID,
            f"Google 返回 HTTP {status_code},Cookie 已被拒绝({hop_text})",
            http_status=status_code,
            location=location,
            cookie_names=list(pairs.keys()),
        )

    if not hops:
        return _result(
            STATUS_UNKNOWN,
            "探测未取得任何响应,无法判定 Cookie 状态",
            cookie_names=list(pairs.keys()),
        )

    return _result(
        STATUS_UNKNOWN,
        f"重定向次数超过 {MAX_PROBE_HOPS} 跳({hop_text}),无法判定 Cookie 状态",
        http_status=status_code,
        location=location,
        cookie_names=list(pairs.keys()),
    )


class GoogleCookieHealthChecker:
    """带缓存与后台巡检的 Google Cookies 健康检查器。"""

    def __init__(self) -> None:
        self.db: Any = None
        self._entries: Dict[int, Dict[str, Any]] = {}
        self._tasks: Dict[int, asyncio.Task] = {}
        self._warned: Dict[int, str] = {}
        self._loop_task: Optional[asyncio.Task] = None

    # ---------- 配置 / 工具 ----------

    @property
    def enabled(self) -> bool:
        return bool(config.google_cookie_health_check_enabled)

    @property
    def ttl_seconds(self) -> float:
        try:
            return max(0.0, float(config.google_cookie_health_check_ttl_seconds))
        except Exception:
            return 600.0

    def configure(self, db: Any) -> None:
        self.db = db

    @staticmethod
    def _token_id(token: Any) -> int:
        try:
            return int(_field(token, "id", 0) or 0)
        except Exception:
            return 0

    @staticmethod
    def _token_email(token: Any) -> str:
        return str(_field(token, "email", "") or "").strip()

    @staticmethod
    def _raw_cookies(token: Any) -> str:
        return str(_field(token, "google_cookies", "") or "").strip()

    def _signature(self, token: Any) -> str:
        raw = self._raw_cookies(token)
        if not raw:
            return ""
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _is_fresh(self, token: Any) -> bool:
        entry = self._entries.get(self._token_id(token))
        if not entry:
            return False
        if entry["signature"] != self._signature(token):
            return False
        return (time.monotonic() - entry["checked_monotonic"]) < self.ttl_seconds

    # ---------- 缓存读取 ----------

    def peek(self, token: Any) -> Dict[str, Any]:
        """只读缓存结论,绝不触发探测。"""
        token_id = self._token_id(token)
        signature = self._signature(token)
        if not signature:
            return {
                "status": STATUS_MISSING,
                "label": status_label(STATUS_MISSING),
                "detail": "未配置 Google Cookies",
                "checked_at": None,
                "age_seconds": None,
                "stale": False,
                "cookie_names": [],
                "problem": self._is_problem(STATUS_MISSING, token),
            }

        entry = self._entries.get(token_id)
        if not entry or entry["signature"] != signature:
            return {
                "status": STATUS_UNCHECKED,
                "label": status_label(STATUS_UNCHECKED),
                "detail": "尚未检查(或 Cookie 已被修改,结论已作废)",
                "checked_at": None,
                "age_seconds": None,
                "stale": True,
                "cookie_names": [],
                "problem": False,
            }

        age = time.monotonic() - entry["checked_monotonic"]
        result = dict(entry["result"])
        status = result.get("status") or STATUS_UNKNOWN
        return {
            "status": status,
            "label": status_label(status),
            "detail": result.get("detail") or "",
            "checked_at": entry["checked_at"],
            "age_seconds": round(age, 1),
            "stale": age >= self.ttl_seconds,
            "cookie_names": result.get("cookie_names") or [],
            "http_status": result.get("http_status"),
            "probe_url": entry.get("probe_url"),
            "problem": self._is_problem(status, token),
        }

    @staticmethod
    def _is_problem(status: str, token: Any) -> bool:
        if status in PROBLEM_STATUSES:
            return True
        if status == STATUS_MISSING:
            mode = str(_field(token, "protocol_mode", "") or "").strip().lower()
            return mode in MISSING_WORTH_WARNING_MODES
        return False

    def summarize(self, tokens: Iterable[Any]) -> Dict[str, int]:
        summary = {
            "total": 0,
            "valid": 0,
            "invalid": 0,
            "incomplete": 0,
            "missing": 0,
            "unknown": 0,
            "unchecked": 0,
            "problems": 0,
        }
        for token in tokens or []:
            summary["total"] += 1
            public = self.peek(token)
            status = public.get("status") or STATUS_UNCHECKED
            if status in summary:
                summary[status] += 1
            else:
                summary["unchecked"] += 1
            if public.get("problem"):
                summary["problems"] += 1
        return summary

    # ---------- 探测 ----------

    async def check_token(self, token: Any, *, reason: str = "manual") -> Dict[str, Any]:
        """立即探测并写入缓存,返回可展示的状态字典。"""
        token_id = self._token_id(token)
        raw_cookies = self._raw_cookies(token)
        signature = self._signature(token)

        if not raw_cookies:
            result = _result(STATUS_MISSING, "未配置 Google Cookies")
        else:
            probe_url = (config.google_cookie_health_probe_url or DEFAULT_PROBE_URL).strip()
            result = await probe_google_cookies(
                build_google_cookie_header(raw_cookies),
                probe_url=probe_url,
                proxy_url=str(_field(token, "proxy_url", "") or "").strip() or None,
            )
            result["probe_url"] = probe_url

        checked_monotonic = time.monotonic()
        checked_at = datetime.now(timezone.utc).isoformat()
        if token_id:
            self._entries[token_id] = {
                "signature": signature,
                "result": result,
                "checked_monotonic": checked_monotonic,
                "checked_at": checked_at,
                "probe_url": result.get("probe_url") or "",
            }

        self._log_transition(token, result, reason=reason)

        status = result.get("status") or STATUS_UNKNOWN
        return {
            "status": status,
            "label": status_label(status),
            "detail": result.get("detail") or "",
            "checked_at": checked_at,
            "age_seconds": 0.0,
            "stale": False,
            "cookie_names": result.get("cookie_names") or [],
            "http_status": result.get("http_status"),
            "probe_url": result.get("probe_url"),
            "problem": self._is_problem(status, token),
        }

    def _log_transition(self, token: Any, result: Dict[str, Any], *, reason: str) -> None:
        token_id = self._token_id(token)
        email = self._token_email(token) or "未知账号"
        status = result.get("status") or STATUS_UNKNOWN
        detail = result.get("detail") or ""
        signature = self._signature(token)

        if status in PROBLEM_STATUSES:
            # 同一份失效 Cookie 只告警一次,避免每轮巡检刷屏
            if self._warned.get(token_id) != signature:
                self._warned[token_id] = signature
                debug_logger.log_warning(
                    f"[凭证健康] Token {token_id}({email}) {status_label(status)}:{detail};"
                    "受影响:flow.google.com 应用页无法登录、协议模式无法刷新 ST、"
                    "上游可能返回 401/403(与打码无关)。"
                    "请在已登录的浏览器中重新导出 .google.com 的账号 Cookies 后覆盖配置"
                    f"(触发原因: {reason})"
                )
        elif status == STATUS_VALID and self._warned.pop(token_id, None):
            debug_logger.log_info(
                f"[凭证健康] Token {token_id}({email}) Google Cookies 已恢复有效"
            )

    async def get_status(self, token: Any, *, refresh: bool = False) -> Dict[str, Any]:
        """读取状态;必要时调度一次后台探测,不阻塞调用方。"""
        if not self.enabled:
            return {
                "status": STATUS_UNCHECKED,
                "label": "健康检查已关闭",
                "detail": "Google Cookies 健康检查已被配置关闭",
                "checked_at": None,
                "age_seconds": None,
                "stale": True,
                "cookie_names": [],
                "problem": False,
            }
        if refresh:
            return await self.check_token(token, reason="manual")
        public = self.peek(token)
        if self._raw_cookies(token) and (public.get("stale") or public.get("status") == STATUS_UNCHECKED):
            self.schedule(token)
        return public

    def schedule(self, token: Any, *, force: bool = False, reason: str = "auto") -> None:
        """把探测排进后台,不阻塞请求。(同一 token 只保留一个在跑的任务)"""
        if not self.enabled:
            return
        token_id = self._token_id(token)
        if not token_id or not self._raw_cookies(token):
            return
        existing = self._tasks.get(token_id)
        if existing and not existing.done():
            return
        if not force and self._is_fresh(token):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        task = loop.create_task(self.check_token(token, reason=reason))
        self._tasks[token_id] = task
        task.add_done_callback(lambda finished, tid=token_id: self._on_task_done(tid, finished))

    def _on_task_done(self, token_id: int, task: asyncio.Task) -> None:
        if self._tasks.get(token_id) is task:
            self._tasks.pop(token_id, None)
        if task.cancelled():
            return
        exc = task.exception()
        if exc:
            debug_logger.log_warning(
                f"[凭证健康] Token {token_id} 后台检查异常: {type(exc).__name__}: {exc}"
            )

    def schedule_stale(self, tokens: Iterable[Any], *, reason: str = "sweep") -> int:
        scheduled = 0
        for token in tokens or []:
            if not self._raw_cookies(token):
                continue
            if self._is_fresh(token):
                continue
            before = self._tasks.get(self._token_id(token))
            self.schedule(token, force=True, reason=reason)
            if self._tasks.get(self._token_id(token)) is not before:
                scheduled += 1
        return scheduled

    # ---------- 后台巡检 ----------

    async def sweep_once(self) -> int:
        """巡检一轮:把已配置 google_cookies 且结论过期的 token 逐个探测一遍。"""
        if not self.enabled or self.db is None:
            return 0
        try:
            tokens = await self.db.get_active_tokens()
        except Exception as exc:
            debug_logger.log_warning(f"[凭证健康] 读取 Token 列表失败: {exc}")
            return 0

        checked = 0
        for token in tokens or []:
            if not self._raw_cookies(token):
                continue
            if self._is_fresh(token):
                continue
            try:
                await self.check_token(token, reason="sweep")
                checked += 1
            except Exception as exc:
                debug_logger.log_warning(
                    f"[凭证健康] Token {self._token_id(token)} 巡检异常: {exc}"
                )
            await asyncio.sleep(0.5)
        return checked

    async def _sweep_loop(self) -> None:
        # 启动后先等一会儿,避免和浏览器预热争抢资源
        await asyncio.sleep(20)
        while True:
            try:
                await self.sweep_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                debug_logger.log_warning(f"[凭证健康] 巡检任务异常: {exc}")
            try:
                interval = max(30.0, float(config.google_cookie_health_sweep_interval_seconds))
            except Exception:
                interval = 300.0
            await asyncio.sleep(interval)

    def start(self) -> None:
        if not self.enabled:
            debug_logger.log_info("[凭证健康] Google Cookies 健康巡检已关闭(配置项 google_cookie_health_check_enabled=false)")
            return
        if self._loop_task and not self._loop_task.done():
            return
        self._loop_task = asyncio.create_task(self._sweep_loop())

    async def stop(self) -> None:
        task = self._loop_task
        self._loop_task = None
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception as exc:
                debug_logger.log_warning(f"[凭证健康] 停止巡检任务时出错: {exc}")


google_cookie_health = GoogleCookieHealthChecker()
