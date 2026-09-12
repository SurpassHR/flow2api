"""服务器自持凭证浏览器(credential keeper)。

## 为什么需要它

此前服务器的凭证完全依赖**本地浏览器插件**每隔一段时间把 ST 推到上游接口。
一旦插件停止推送、或推来的是失效会话,服务就彻底失去自续期能力——因为服务器
自己没有任何"登录过的浏览器"可以重新签发会话。

但这条路其实不必如此:只要服务器持有**一个登录过的浏览器 profile**,
它就能像真人浏览器一样自己维持会话、自己读出凭证。于是本地浏览器从
"生命线"退化为"可选的引导手段"。

## 做法

- 用 Playwright 的 ``launch_persistent_context`` 打开一个 Chromium,profile 落在
  磁盘上(可用 ``credential_keeper_profile_dir`` 指向 bind-mount 目录),
  因此**进程重启、容器重建都不会丢登录态**。
- 周期性访问 ``labs.google`` 保持会话活跃,并直接从浏览器上下文读出:
  - ``__Secure-next-auth.session-token`` → ``Token.st``
  - ``.google.com`` 账号 Cookie(SID/HSID/SSID/APISID/SAPISID…) → ``Token.google_cookies``
- 写库后调用 ``token_manager`` 刷新 AT,服务器即可长期自持。

## 一次性登录怎么完成

``headless = false`` + ``DISPLAY``(Xvfb)下浏览器是有界面的。管理台通过
``/api/credential-keeper/screenshot`` 拉取实时画面,并用 ``/click``、``/type``、
``/key``、``/goto`` 转发输入,于是在服务器上就能直接完成 Google 登录,
**不需要本机参与,也不需要额外安装 VNC**。

## 内存策略(1GB 小机器友好)

普通周期提取是"开浏览器 → 导航 → 读 Cookie → 关浏览器",profile 留在磁盘,
所以内存只在提取那几十秒内短暂升高;只有用户手动打开登录窗口时才常驻。
"""

import asyncio
import json
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from ..core.config import config
from ..core.logger import debug_logger


# NextAuth 会话 cookie 的名字(不同部署/域名可能不同)
SESSION_COOKIE_NAMES = (
    "__Secure-next-auth.session-token",
    "__Host-next-auth.session-token",
    "next-auth.session-token",
)

# Google 账号态 Cookie 的采集与导出规则(2026-09-11 实测)
#
# 背景:协议登录(protocol_login)只要求 SID/HSID/SSID/APISID/SAPISID 至少存在一个,
# 但"能开始登录"和"会话被 Google 认"是两回事 —— 同一个账号在浏览器里明明是登录态,
# 把这套 Cookie 拉平成 HTTP 请求头之后,myaccount.google.com 却 302 回登录页。
# 实测排除项:SID/HSID 并非必需(缺了也照样有效),说明 Google 现在靠
# __Secure-*PSID/PSIDTS/PSIDCC(会话轮转)、OSID/__Secure-OSID、__Secure-STRP、
# OTZ/NID/AEC 这一整套判定会话;少的正是轮转/账号那一撮,不是指纹也不是 IP。
#
# 所以这里不再用白名单"挑名字",而是把浏览器里 google.com 域的账号 Cookie 全量导出,
# 只排除三类:
# - 分析/广告/本地偏好:_ga*(含 _ga_XXXX)、_gid、_gcl*、_utm*;
# - ``__Host-*``:按 RFC 6265 只能发给原 host,拉平成通用 Cookie 头反而无效;
# - 一次性登录中间态:SMSV(会话迁移)。
#
# GOOGLE_COOKIE_PRIORITY 只决定写进 Cookie 头的顺序(便于比对与面板展示),
# 不参与过滤;不在其中的名字按名字排序追加在后面。
GOOGLE_COOKIE_PRIORITY = (
    "SID",
    "HSID",
    "SSID",
    "APISID",
    "SAPISID",
    "LSID",
    "OSID",
    "OTZ",
    "NID",
    "AEC",
    "ACCOUNT_CHOOSER",
    "__Secure-STRP",
    "SIDCC",
    "__Secure-1PSID",
    "__Secure-3PSID",
    "__Secure-OSID",
    "__Secure-1PAPISID",
    "__Secure-3PAPISID",
    "__Secure-1PSIDTS",
    "__Secure-3PSIDTS",
    "__Secure-1PSIDCC",
    "__Secure-3PSIDCC",
    "__Secure-ENID",
)
GOOGLE_COOKIE_EXCLUDE_PREFIXES = ("_ga", "_gid", "_gcl", "_utm", "__Host-")
GOOGLE_COOKIE_EXCLUDE_NAMES = ("SMSV", "GAPS")

# 让浏览器自己去账号页走一趟,把 __Secure-*PSIDTS / __Secure-STRP / OSID 这些
# "访问时才下发/轮转"的账号态 Cookie 续上;只停在 labs/flow.google.com 上会慢慢变旧。
GOOGLE_ACCOUNT_HARVEST_URLS = (
    "https://accounts.google.com/",
    "https://myaccount.google.com/",
)

# 兼容旧引用:账号 Cookie 的导出优先顺序。
GOOGLE_ACCOUNT_COOKIE_NAMES = GOOGLE_COOKIE_PRIORITY


def _is_exportable_google_cookie(name: str) -> bool:
    """判断某个 Cookie 名字是否应当被导出(见上方规则)。"""
    clean = str(name or "").strip()
    if not clean:
        return False
    if clean in GOOGLE_COOKIE_EXCLUDE_NAMES:
        return False
    for prefix in GOOGLE_COOKIE_EXCLUDE_PREFIXES:
        if clean.startswith(prefix):
            return False
    return True

# 默认登录页:必须在 labs.google 的 NextAuth 上完成登录,
# 只在 flow.google.com 登录不会刷新插件读取的那枚会话 cookie。
DEFAULT_SIGNIN_URL = (
    "https://labs.google/fx/api/auth/signin"
    "?callbackUrl=https%3A%2F%2Flabs.google%2F"
)

# 持久 profile 里可能残留上次异常退出的单例锁,不清掉会导致无法再次启动。
_PROFILE_LOCK_FILES = ("SingletonLock", "SingletonCookie", "SingletonSocket")

VIEWPORT = {"width": 1440, "height": 900}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def model_error(exc: BaseException) -> str:
    """把异常压成一行可读原因(供日志与告警展示)。"""
    return f"{type(exc).__name__}: {str(exc)[:160]}"


def classify_url(url: str) -> str:
    """按浏览器落点 URL 判断登录态。

    返回 ``logged_in`` / ``needs_login`` / ``unknown``。
    """
    target = (url or "").strip()
    if not target:
        return "unknown"
    low = target.lower()
    host = (urlparse(target).netloc or "").lower()
    if host.endswith("accounts.google.com") or "servicelogin" in low:
        return "needs_login"
    if "/signin" in low:
        return "needs_login"
    if host.endswith("labs.google") or host.endswith("flow.google.com"):
        return "logged_in"
    return "unknown"


def extract_session_token(cookies: List[Dict[str, Any]]) -> str:
    """从浏览器 cookie 列表里挑出 labs.google 的 NextAuth 会话 token。"""
    for cookie in cookies or []:
        name = str(cookie.get("name") or "")
        if name not in SESSION_COOKIE_NAMES:
            continue
        domain = str(cookie.get("domain") or "").lstrip(".").lower()
        if not domain.endswith("labs.google"):
            continue
        value = str(cookie.get("value") or "").strip()
        if value:
            return value
    return ""


def classify_login_state(url: str, cookies: Optional[List[Dict[str, Any]]] = None) -> str:
    """综合 URL 与 cookie 判断登录态。

    2026-09-11 实测:匿名访问 ``https://labs.google/`` 时页面**不会跳转**到登录页,
    因此只按 URL 判断会把未登录误判成已登录(后续提取才报"拿不到会话 cookie")。
    这里以"是否存在 labs.google 的 NextAuth 会话 cookie"为主判据,URL 只用来区分
    "被重定向到登录页"与"其它异常落点"。
    """
    if cookies is not None and extract_session_token(cookies):
        return "logged_in"
    by_url = classify_url(url)
    if by_url == "needs_login":
        return "needs_login"
    if by_url == "logged_in":
        # 站点加载了但没有会话 cookie → 仍是未登录(通常是匿名落地页)
        return "needs_login"
    return "unknown"


def extract_google_cookies(cookies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把浏览器里 google.com 域的账号态 Cookie **全量**导出。

    返回 JSON 可序列化列表(``protocol_login._parse_google_cookies`` 直接支持该格式)。

    - 只保留 host 以 ``google.com`` 结尾的 Cookie(``.google.com`` /
      ``accounts.google.com`` / ``flow.google.com`` / ``labs.google`` 等),
      并排除分析类与 ``__Host-*``(见 ``_is_exportable_google_cookie``);
    - 同名 Cookie 在不同 host 下可能重复,优先取**域级**(``.google.com``)那一份:
      拉平成通用 Cookie 头时它更接近浏览器真实发出的内容;
    - 没有域级那份时保留 host 级的值 —— 这一步不能省:实测 profile 里
      OSID/__Secure-OSID **只**存在于 ``flow.google.com`` 下,而它们正是
      Google 判定账号态所需的一项。
    - 输出顺序固定为 ``GOOGLE_COOKIE_PRIORITY``,其余名字按名字排序追加,
      保证每次导出的头部稳定、便于前后对比。
    """
    best: Dict[str, Dict[str, Any]] = {}
    for cookie in cookies or []:
        name = str(cookie.get("name") or "").strip()
        if not _is_exportable_google_cookie(name):
            continue
        raw_domain = str(cookie.get("domain") or "")
        host = raw_domain.lstrip(".").lower()
        if not host.endswith("google.com"):
            continue
        value = str(cookie.get("value") or "").strip()
        if not value:
            continue
        domain_wide = raw_domain.startswith(".")
        current = best.get(name)
        if current is None or (domain_wide and not current["_domain_wide"]):
            best[name] = {
                "name": name,
                "value": value,
                "domain": raw_domain,
                "path": str(cookie.get("path") or "/"),
                "_domain_wide": domain_wide,
            }

    ordered = [name for name in GOOGLE_COOKIE_PRIORITY if name in best]
    ordered += sorted(name for name in best if name not in GOOGLE_COOKIE_PRIORITY)
    picked: List[Dict[str, Any]] = []
    for name in ordered:
        item = best[name]
        item.pop("_domain_wide", None)
        picked.append(item)
    return picked


def _parse_google_cookie_pairs(raw: Any) -> Dict[str, str]:
    """把库里已有的 google_cookies(flat 文本或 JSON)解析成 name → value。"""
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        from .protocol_login import _parse_google_cookies

        parsed = _parse_google_cookies(text)
    except Exception:
        parsed = {}
    if parsed:
        return {str(k).strip(): str(v).strip() for k, v in parsed.items() if str(v).strip()}
    result: Dict[str, str] = {}
    for chunk in text.split(";"):
        segment = chunk.strip()
        if not segment or "=" not in segment:
            continue
        name, _, value = segment.partition("=")
        if name.strip() and value.strip():
            result[name.strip()] = value.strip()
    return result


def serialize_google_cookie_text(items: List[Dict[str, Any]]) -> str:
    """按浏览器插件 / Cookie-Editor 的习惯导出 ``NAME=value;NAME=value``。

    用 flat 文本(而不是 JSON)写库有两个好处:面板里能直接和本地导出对比,
    而且这就是用户实测“能恢复正常”的那种格式。
    """
    parts: List[str] = []
    for item in items or []:
        name = str((item or {}).get("name") or "").strip()
        value = str((item or {}).get("value") or "").strip()
        if name and value:
            parts.append(f"{name}={value}")
    return ";".join(parts)


def merge_google_cookie_text(existing_raw: Any, new_items: List[Dict[str, Any]]) -> str:
    """把本轮采集到的账号 Cookie 合并进库里已有的那份。

    规则是**只增不减**:本轮采到的同名 Cookie 覆盖旧值(更新鲜),库里已有、
    本轮没采到的名字原样保留。

    这条规则是必需的:采集可能不完整(浏览器还没去过 accounts.google.com、
    或某一轮刚好少几个),整体覆盖会把库里已经验证可用的集合打坏 ——
    实测就是这样把一套能从 HTTP 侧通过体检的 Cookie 覆盖成一个被判未登录的子集。
    """
    merged = _parse_google_cookie_pairs(existing_raw)
    for item in new_items or []:
        name = str((item or {}).get("name") or "").strip()
        value = str((item or {}).get("value") or "").strip()
        if name and value:
            merged[name] = value
    ordered = [name for name in GOOGLE_COOKIE_PRIORITY if name in merged]
    ordered += sorted(name for name in merged if name not in GOOGLE_COOKIE_PRIORITY)
    return ";".join(f"{name}={merged[name]}" for name in ordered)


def _free_mb() -> Optional[int]:
    """读取 /proc/meminfo 的 MemAvailable(MB);读不到时返回 None(不拦截)。"""
    try:
        with open("/proc/meminfo", "r", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("MemAvailable:"):
                    return int(int(line.split()[1]) / 1024)
    except Exception:
        return None
    return None


def _captcha_busy() -> bool:
    """打码服务是否正在忙(用于把浏览器资源让给打码)。

    只做只读探测,任何异常都按"不忙"处理,避免影响凭证逻辑本身。
    """
    try:
        from .browser_captcha import BrowserCaptchaService

        instance = getattr(BrowserCaptchaService, "_instance", None)
        if instance is None:
            return False
        for slot_id in list(getattr(instance, "_browsers", {}) or {}):
            try:
                if instance._is_slot_busy_for_allocation(slot_id):
                    return True
            except Exception:
                continue
        return bool(getattr(instance, "_slot_reservations", {}) or {})
    except Exception:
        return False


class BrowserNotOpen(RuntimeError):
    """浏览器当前未打开(远程控制类接口不应隐式拉起浏览器)。"""


class CredentialKeeper:
    """服务器自持的凭证浏览器。"""

    def __init__(self) -> None:
        self._db = None
        self._token_manager = None

        self._playwright = None
        self._context = None
        self._page = None

        self._lock = asyncio.Lock()
        self._refresh_lock = asyncio.Lock()
        self._task: Optional[asyncio.Task] = None
        self._stopping = False

        self._hold_open = False
        self._login_state = "not_started"
        self._current_url = ""
        self._last_run_at = ""
        self._last_result = ""
        self._last_error = ""
        self._last_extract: Dict[str, Any] = {}
        self._next_run_ts = 0.0
        self._refresh_count = 0
        self._last_success_at = ""

    # ------------------------------------------------------------------ 配置

    def configure(self, db, token_manager=None) -> "CredentialKeeper":
        self._db = db
        if token_manager is not None:
            self._token_manager = token_manager
        return self

    @property
    def enabled(self) -> bool:
        return bool(getattr(config, "credential_keeper_enabled", False))

    def _headless(self) -> bool:
        return bool(getattr(config, "credential_keeper_headless", False))

    def _interval_seconds(self) -> int:
        return int(getattr(config, "credential_keeper_interval_seconds", 1800))

    def _startup_delay_seconds(self) -> int:
        return int(getattr(config, "credential_keeper_startup_delay_seconds", 30))

    def _nav_timeout_ms(self) -> int:
        return int(getattr(config, "credential_keeper_nav_timeout_seconds", 45)) * 1000

    def _target_url(self) -> str:
        value = str(getattr(config, "credential_keeper_target_url", "") or "").strip()
        return value or "https://labs.google/fx/tools/flow"

    def _auto_write(self) -> bool:
        return bool(getattr(config, "credential_keeper_auto_write", True))

    def _skip_when_captcha_busy(self) -> bool:
        return bool(getattr(config, "credential_keeper_skip_when_captcha_busy", True))

    def _disable_passkey(self) -> bool:
        return bool(getattr(config, "credential_keeper_disable_passkey", True))

    def _min_free_mb(self) -> int:
        return int(getattr(config, "credential_keeper_min_free_mb", 150))

    def _needs_login_retry_seconds(self) -> int:
        return int(getattr(config, "credential_keeper_needs_login_retry_seconds", 300))

    def _profile_dir(self) -> str:
        raw = str(getattr(config, "credential_keeper_profile_dir", "") or "").strip()
        path = Path(raw).expanduser() if raw else Path(os.getcwd()) / "browser_profile_keeper"
        path.mkdir(parents=True, exist_ok=True)
        return str(path)

    # ------------------------------------------------------------ 浏览器生命周期

    def _purge_stale_profile_locks(self) -> None:
        profile = Path(self._profile_dir())
        for name in _PROFILE_LOCK_FILES:
            target = profile / name
            try:
                if target.is_symlink() or target.exists() and not target.is_dir():
                    target.unlink()
                elif target.exists():
                    shutil.rmtree(target, ignore_errors=True)
            except Exception:
                pass

    def _browser_args(self) -> List[str]:
        width = VIEWPORT["width"]
        height = VIEWPORT["height"]
        return [
            "--disable-blink-features=AutomationControlled",
            "--lang=en-US",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-setuid-sandbox",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-infobars",
            "--hide-scrollbars",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-translate",
            "--disable-default-apps",
            # Xvfb 下窗口容易被 Chromium 判定为“被遮挡/不可见”:一旦页面被后台化甚至冻结,
            # 截图仍然正常(渲染资源还在),但鼠标/键盘转发全部石沉大海。
            "--disable-backgrounding-occluded-windows",
            "--disable-renderer-backgrounding",
            "--disable-background-timer-throttling",
            "--disable-features=CalculateNativeWinOcclusion",
            f"--window-size={width},{height}",
        ]

    async def _ensure_browser(self):
        """确保浏览器已启动并返回当前 page。"""
        async with self._lock:
            if self._page is not None and not self._page.is_closed():
                return self._page
            await self._launch_locked()
            return self._page

    async def _launch_locked(self) -> None:
        if self._page is not None and not self._page.is_closed():
            return

        from playwright.async_api import async_playwright

        headless = self._headless()
        if not headless and not os.environ.get("DISPLAY"):
            debug_logger.log_warning(
                "[CredentialKeeper] 有头模式已启用但 DISPLAY 未设置,"
                "登录窗口将不可见(可设置 headless=true 或提供 Xvfb)"
            )

        self._purge_stale_profile_locks()
        profile_dir = self._profile_dir()

        launch_kwargs: Dict[str, Any] = dict(
            user_data_dir=profile_dir,
            headless=headless,
            locale="en-US",
            viewport=dict(VIEWPORT),
            args=self._browser_args(),
        )
        executable = os.environ.get("BROWSER_EXECUTABLE_PATH", "").strip()
        if executable:
            launch_kwargs["executable_path"] = executable

        playwright = await async_playwright().start()
        try:
            context = await playwright.chromium.launch_persistent_context(**launch_kwargs)
        except Exception:
            try:
                await playwright.stop()
            except Exception:
                pass
            raise

        self._playwright = playwright
        self._context = context
        await self._install_passkey_guard(context)
        self._page = context.pages[0] if context.pages else await context.new_page()
        self._watch_new_pages(context)
        try:
            self._page.set_default_timeout(self._nav_timeout_ms())
        except Exception:
            pass
        await self._hydrate_from_db()
        debug_logger.log_info(
            f"[CredentialKeeper] 凭证浏览器已启动(headless={headless}, profile={profile_dir})"
        )

    async def _install_passkey_guard(self, context) -> None:
        """让页面上根本用不到通行密钥。

        服务器上的 Chromium 没有任何可用认证器:页面一旦真的发起 WebAuthn 请求,
        Chrome 会弹出一个原生选择窗口——它在 Xvfb 里没人能点,而且是模态的,
        页面从此收不到任何鼠标/键盘事件。表现就是画面定格在
        “Verifying it's you… / Complete sign-in using your passkey”,
        连 Try another way 和 Tab 都失效。
        这里直接让 credentials.get/create 立即失败、平台认证器报告为不可用,
        Google 就会退回密码/验证码等可在远程操作的方式。
        """
        if not self._disable_passkey():
            return
        script = """
        (() => {
            const deny = () => Promise.reject(new DOMException(
                'The operation either timed out or was not allowed.', 'NotAllowedError'));
            try {
                const container = navigator.credentials;
                if (container) {
                    container.get = deny;
                    container.create = deny;
                }
                const pkc = window.PublicKeyCredential;
                if (pkc) {
                    pkc.isUserVerifyingPlatformAuthenticatorAvailable = async () => false;
                    if (pkc.isConditionalMediationAvailable) {
                        pkc.isConditionalMediationAvailable = async () => false;
                    }
                }
            } catch (error) { /* 拿不到就保持原样 */ }
        })();
        """
        try:
            await context.add_init_script(script)
            debug_logger.log_info(
                "[CredentialKeeper] 已禁用页面通行密钥(passkey)能力,避免卡在原生选择窗口"
            )
        except Exception as exc:
            debug_logger.log_warning(f"[CredentialKeeper] 安装 passkey 拦截脚本失败: {exc}")

    def _watch_new_pages(self, context) -> None:
        """监听新页签/弹窗。

        Google 登录流程会在第二步另开一个窗口(如“Try another way”的方式选择窗),
        新窗口才是真正该操作的那一个;不接管的话截图/点击都还停在旧页上,
        表现就是“画面里点不动、Tab 也切不动焦点”。
        """
        def _on_page(page) -> None:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop is None:
                self._adopt_page(page)
                return
            loop.create_task(self._adopt_page_async(page))

        try:
            context.on("page", _on_page)
        except Exception:
            pass

    def _adopt_page(self, page) -> None:
        try:
            if page.is_closed():
                return
        except Exception:
            return
        self._page = page
        self._current_url = str(getattr(page, "url", "") or "")

    async def _adopt_page_async(self, page) -> None:
        self._adopt_page(page)
        try:
            await page.wait_for_timeout(300)
            await self._activate(page)
            self._current_url = str(page.url or "") or self._current_url
        except Exception:
            pass
        debug_logger.log_info(f"[CredentialKeeper] 已接管新页面: {self._current_url[:140]}")

    def list_pages(self) -> List[Dict[str, Any]]:
        """当前浏览器里所有页签/弹窗,管理台据此切换要操作的那一个。"""
        context = self._context
        if context is None:
            return []
        try:
            pages = list(context.pages)
        except Exception:
            return []
        items: List[Dict[str, Any]] = []
        for index, page in enumerate(pages):
            try:
                if page.is_closed():
                    continue
                items.append(
                    {
                        "index": index,
                        "url": str(page.url or "")[:200],
                        "current": page is self._page,
                    }
                )
            except Exception:
                continue
        return items

    async def select_page(self, index: int) -> Dict[str, Any]:
        context = self._context
        if context is None:
            raise BrowserNotOpen("凭证浏览器未打开,请先点击“打开登录窗口”")
        pages = [page for page in list(context.pages) if not page.is_closed()]
        if index < 0 or index >= len(pages):
            raise ValueError(f"页面序号越界(可选 0-{max(len(pages) - 1, 0)})")
        page = pages[index]
        self._page = page
        await self._activate(page)
        self._current_url = str(page.url or "")
        debug_logger.log_info(f"[CredentialKeeper] 手动切换页面 #{index}: {self._current_url[:140]}")
        return {"index": index, "url": self._current_url}

    async def close(self) -> None:
        """关闭浏览器但保留磁盘上的 profile(登录态因此不会丢)。"""
        async with self._lock:
            await self._close_locked()

    async def _close_locked(self) -> None:
        context, playwright = self._context, self._playwright
        self._context = None
        self._playwright = None
        self._page = None
        self._hold_open = False
        if context is not None:
            try:
                await context.close()
            except Exception:
                pass
        if playwright is not None:
            try:
                await playwright.stop()
            except Exception:
                pass

    # ------------------------------------------------------------------ 导航/提取

    async def _goto(self, url: str, *, settle_ms: int = 2500) -> str:
        page = await self._ensure_browser()
        last_error = ""
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=self._nav_timeout_ms())
        except Exception as exc:
            # 导航超时/被中断时页面往往已经到位,继续按当前 URL 判定
            last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
        try:
            await page.wait_for_timeout(settle_ms)
        except Exception:
            pass
        current = ""
        try:
            current = str(page.url or "")
        except Exception:
            current = ""
        self._current_url = current
        if last_error and not current:
            raise RuntimeError(last_error)
        return current

    def _live_page(self):
        """返回当前可用的 page;已接管的那页被关掉时回退到其它还开着的页。"""
        page = self._page
        try:
            if page is not None and not page.is_closed():
                return page
        except Exception:
            pass
        context = self._context
        if context is not None:
            try:
                for candidate in reversed(list(context.pages)):
                    if not candidate.is_closed():
                        self._page = candidate
                        self._current_url = str(candidate.url or "") or self._current_url
                        debug_logger.log_info(
                            f"[CredentialKeeper] 原页面已关闭,回退到: {self._current_url[:140]}"
                        )
                        return candidate
            except Exception:
                pass
        return None

    def _require_browser(self):
        """远程控制专用:浏览器没开着就直接报错。

        否则管理台每次轮询截图都会隐式拉起一个 Chromium——在小内存机器上不可接受。
        """
        page = self._live_page()
        if page is None:
            raise BrowserNotOpen("凭证浏览器未打开,请先点击“打开登录窗口”")
        return page

    async def _read_cookies(self) -> List[Dict[str, Any]]:
        if self._context is None:
            return []
        try:
            return list(await self._context.cookies())
        except Exception as exc:
            debug_logger.log_warning(f"[CredentialKeeper] 读取 cookie 失败: {exc}")
            return []

    def _harvest_enabled(self) -> bool:
        return bool(getattr(config, "credential_keeper_harvest_account_cookies", True))

    async def _harvest_google_account_cookies(self) -> Dict[str, Any]:
        """让浏览器自己到 Google 账号页走一趟,把账号态 Cookie 续上。

    为什么需要:profile 里那套 Cookie 是上一次登录流程留下的,而
    ``__Secure-*PSIDTS``(会话轮转时间戳)、``__Secure-STRP``、``OSID`` 这些
    是 accounts.google.com 在**访问时**下发/轮转的;只停在 labs.google /
    flow.google.com 上,它们会慢慢变旧 —— 实测表现就是"浏览器里还是登录态,
    拉平成 HTTP 头却被 302 回登录页"。

    用 ``context.request``(与浏览器共用 Cookie jar)而不是新开页面:既不会
    打扰管理台正在看的画面,也不会触发"新页签自动接管";但响应里的 Set-Cookie
    会正常写回 profile,所以效果等于浏览器亲自访问。
    """
        out: Dict[str, Any] = {"visited": [], "failed": [], "session_alive": None}
        if self._context is None or not self._harvest_enabled():
            out["skipped"] = True
            return out
        for url in GOOGLE_ACCOUNT_HARVEST_URLS:
            try:
                response = await self._context.request.get(
                    url,
                    timeout=self._nav_timeout_ms(),
                    fail_on_status_code=False,
                    max_redirects=5,
                )
            except Exception as exc:
                out["failed"].append(f"{url} {model_error(exc)}")
                continue
            try:
                final_url = str(getattr(response, "url", "") or "")
                status = int(getattr(response, "status", 0) or 0)
                out["visited"].append(f"{status} {final_url[:120] or url}")
                if out["session_alive"] is None:
                    low = final_url.lower()
                    out["session_alive"] = "servicelogin" not in low and "/signin" not in low
            finally:
                try:
                    await response.dispose()
                except Exception:
                    pass
        if out["visited"] or out["failed"]:
            detail = "; ".join(out["visited"] + [f"失败:{item}" for item in out["failed"]])
            debug_logger.log_info(f"[CredentialKeeper] 账号页采集(续期账号 Cookie): {detail}")
        return out

    async def _hydrate_from_db(self) -> bool:
        """把库里的 ST 与 .google.com 账号 Cookie 注入持久 profile。

    持久 profile 是登录态的载体,库是它的备份,两者互为容错:
    profile 丢失(未挂载/被重置)时用库补齐;库里失效时由 profile 重新提取覆盖。
    注意:注入 **不代表会话仍然有效** —— refresh_now 仍会用 ST→AT 真实验证后才写库。
        """
        if not bool(getattr(config, "credential_keeper_hydrate_from_db", True)):
            return False
        if self._context is None:
            return False
        try:
            existing = await self._context.cookies()
        except Exception:
            existing = []
        if extract_session_token(existing):
            return False

        token = await self._resolve_token(None)
        if token is None:
            return False
        st = str(getattr(token, "st", "") or "").strip()
        if not st:
            return False

        try:
            from .protocol_login import _parse_google_cookies

            parsed = _parse_google_cookies(str(getattr(token, "google_cookies", "") or ""))
        except Exception:
            parsed = {}
        pairs = [
            {"name": str(name), "value": str(value)}
            for name, value in (parsed or {}).items()
            if _is_exportable_google_cookie(str(name))
        ]
        if not await self._apply_st_to_profile(st, pairs):
            debug_logger.log_warning("[CredentialKeeper] 从库注入凭证失败")
            return False
        debug_logger.log_info(
            f"[CredentialKeeper] 已把库里的 ST 与 {len(pairs)} 项账号 Cookie "
            "注入持久 profile(仅为补齐,仍需 ST→AT 验证)"
        )
        return True

    async def _apply_st_to_profile(
        self, st: str, google_cookie_items: Optional[List[Dict[str, Any]]] = None
    ) -> bool:
        """把一份确定可用的 ST(及可选账号 Cookie)写进持久 profile。

        只动 labs.google 的会话 cookie 与 .google.com 账号 cookie,不碰其它站点。
        带 expires 是必需的:不带有效期的 cookie 会被 Chromium 当作会话 cookie,
        浏览器一关就丢(2026-09-11 实测),持久 profile 也就白搭了。
        """
        if self._context is None:
            return False
        st = str(st or "").strip()
        if not st:
            return False

        expires = time.time() + 7 * 86400
        cookies: List[Dict[str, Any]] = [
            {
                "name": "__Secure-next-auth.session-token",
                "value": st,
                "domain": "labs.google",
                "path": "/",
                "secure": True,
                "sameSite": "Lax",
                "expires": expires,
            }
        ]
        for item in google_cookie_items or []:
            name = str((item or {}).get("name") or "")
            value = str((item or {}).get("value") or "")
            if not _is_exportable_google_cookie(name) or not value:
                continue
            # 保留原有 host 作用域(如 flow.google.com 的 OSID):域名级 Cookie 写回
            # .google.com 会改变它的作用范围,反而可能和浏览器不一致。
            scope = str((item or {}).get("domain") or "").strip()
            if not scope.lstrip(".").lower().endswith("google.com"):
                scope = ".google.com"
            cookies.append(
                {
                    "name": name,
                    "value": value,
                    "domain": scope,
                    "path": "/",
                    "secure": True,
                    "expires": expires,
                }
            )
        try:
            await self._context.add_cookies(cookies)
        except Exception as exc:
            debug_logger.log_warning(f"[CredentialKeeper] 写入持久 profile 失败: {exc}")
            return False
        return True

    async def _push_cookies_to_protocol(
        self,
        token,
        google_cookies: List[Dict[str, Any]],
        current_st: str,
    ) -> Dict[str, Any]:
        """把刚提取到的 .google.com 账号 Cookie 回灌给纯 HTTP 协议刷新路径。

        两个方向合起来才是"互为备份":
        - 浏览器 → 协议:本方法。新鲜 Cookie 让协议登录重新可用,并**立即**跑一次,
          而不是等最多 refresh_interval_minutes 分钟后的下一次调度。
        - 协议/插件 → 浏览器:refresh_now 里 ST→AT 验证失败时会回退到库里的 ST,
          并把它同步进持久 profile。
        """
        out: Dict[str, Any] = {}
        token_id = int(getattr(token, "id", 0) or 0)
        if not token_id:
            return out

        # 1) 让 Cookie 健康结论立即按新 Cookie 重算(徽标与告警同步纠正)
        try:
            from .credential_health import google_cookie_health

            latest = await self._db.get_token(token_id) or token
            status = await google_cookie_health.check_token(latest, reason="credential-keeper")
            out["cookie_health"] = status.get("status")
            out["cookie_health_label"] = status.get("label")
        except Exception as exc:
            out["cookie_health_error"] = model_error(exc)

        # 2) 立刻跑一次协议刷新,而不是等下一次调度
        try:
            manager = self._token_manager
            if manager is None:
                from ..main import token_manager as manager  # type: ignore
            out["protocol"] = await manager.force_protocol_refresh(token_id)
        except Exception as exc:
            out["protocol"] = {"ok": False, "detail": model_error(exc)}

        # 3) 协议刷新若换到了新的 ST,顺手同步进 profile,让浏览器侧也用上最新的
        try:
            protocol = out.get("protocol") or {}
            if isinstance(protocol, dict) and protocol.get("ok"):
                latest = await self._db.get_token(token_id)
                new_st = str(getattr(latest, "st", "") or "").strip()
                if new_st and new_st != current_st:
                    out["profile_resynced"] = await self._apply_st_to_profile(
                        new_st, google_cookies
                    )
        except Exception as exc:
            out["profile_resync_error"] = model_error(exc)

        debug_logger.log_info(
            f"[CredentialKeeper] Token {token_id}: 账号 Cookie 已回灌协议刷新路径 -> {out}"
        )
        return out

    async def _verify_st(self, st: str) -> Dict[str, Any]:
        """用纯 HTTP 验证 ST 能否换到真正可用的 AT。

        不做这步而直接写库,失效的 ST 会让 token_manager 刷新失败并把 Token 禁用——
        比"不写"的后果更坏。验证过程本身不修改数据库与 Token 状态。
        """
        if not st:
            return {"ok": False, "detail": "ST 为空"}
        try:
            manager = self._token_manager
            if manager is None:
                from ..main import token_manager as manager  # type: ignore
            client = getattr(manager, "flow_client", None)
            if client is None:
                return {"ok": True, "skipped": True, "detail": "无 flow_client,跳过验证"}

            session = await client.st_to_at(st) or {}
            access_token = str(session.get("access_token") or "").strip()
            if not access_token:
                return {"ok": False, "detail": "ST 换 AT 响应缺少 access_token"}
            try:
                credits = await client.get_credits(access_token) or {}
            except Exception as exc:
                return {
                    "ok": False,
                    "detail": f"AT 不可用({model_error(exc)})",
                }
            return {
                "ok": True,
                "credits": credits.get("credits"),
                "expires": session.get("expires"),
                "email": (session.get("user") or {}).get("email"),
                "detail": "",
            }
        except Exception as exc:
            return {"ok": False, "detail": model_error(exc)}

    async def _resolve_token(self, token_id: Optional[int]):
        if self._db is None:
            return None
        target_id = token_id
        if not target_id:
            configured = int(getattr(config, "credential_keeper_token_id", 0) or 0)
            target_id = configured or 0
        if target_id:
            token = await self._db.get_token(int(target_id))
            if token:
                return token
        tokens = await self._db.get_all_tokens()
        for candidate in tokens or []:
            if getattr(candidate, "is_active", False):
                return candidate
        return (tokens or [None])[0]

    async def refresh_now(
        self,
        token_id: Optional[int] = None,
        *,
        reason: str = "manual",
        write_db: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """导航到目标页 → 判定登录态 → 提取 ST/账号 Cookie → 可选写库并刷新 AT。"""
        if self._refresh_lock.locked():
            return {
                "success": False,
                "skipped": True,
                "reason": "已有提取任务正在进行",
                "login_state": self._login_state,
            }

        async with self._refresh_lock:
            started = time.monotonic()
            self._last_run_at = _now_iso()
            self._last_error = ""
            result: Dict[str, Any] = {
                "success": False,
                "reason": reason,
                "login_state": "unknown",
                "url": "",
                "session_token_found": False,
                "session_token_length": 0,
                "google_cookie_count": 0,
            }

            if reason != "manual":
                if self._skip_when_captcha_busy() and _captcha_busy():
                    self._last_result = "打码任务进行中,本轮跳过"
                    result["skipped"] = True
                    result["reason"] = self._last_result
                    return result
                free_mb = _free_mb()
                minimum = self._min_free_mb()
                if free_mb is not None and minimum > 0 and free_mb < minimum:
                    self._last_result = f"可用内存不足({free_mb}MB < {minimum}MB),本轮跳过"
                    result["skipped"] = True
                    result["reason"] = self._last_result
                    debug_logger.log_info(f"[CredentialKeeper] {self._last_result}")
                    return result

            try:
                url = await self._goto(self._target_url())
            except Exception as exc:
                self._last_error = f"打开目标页失败: {type(exc).__name__}: {str(exc)[:160]}"
                self._last_result = self._last_error
                result["error"] = self._last_error
                debug_logger.log_error(f"[CredentialKeeper] {self._last_error}")
                await self._maybe_close_after_cycle()
                return result

            result["url"] = url
            # 先让浏览器到账号页走一趟:__Secure-*PSIDTS / __Secure-STRP / OSID 这些
            # 账号态 Cookie 是访问时下发/轮转的,不续期就会"浏览器里还登录着、HTTP 侧已被
            # 302"(实测)。采集失败不影响主流程,只是本轮 Cookie 偏旧。
            harvest = await self._harvest_google_account_cookies()
            if not harvest.get("skipped"):
                result["account_harvest"] = harvest
                if harvest.get("session_alive") is False:
                    debug_logger.log_warning(
                        "[CredentialKeeper] 浏览器自身的 Google 账号会话已失效"
                        "(账号页跳到了登录/ServiceLogin),请重新登录"
                    )
            cookies = await self._read_cookies()
            session_token = extract_session_token(cookies)
            google_cookies = extract_google_cookies(cookies)
            state = classify_login_state(url, cookies)
            self._login_state = state
            result["login_state"] = state

            result["session_token_found"] = bool(session_token)
            result["session_token_length"] = len(session_token)
            result["google_cookie_count"] = len(google_cookies)
            self._last_extract = {
                "session_token_found": bool(session_token),
                "session_token_length": len(session_token),
                "google_cookie_count": len(google_cookies),
                "google_cookie_names": [item["name"] for item in google_cookies],
                "account_harvest": harvest,
                "at": self._last_run_at,
            }

            if state != "logged_in" or not session_token:
                if state == "needs_login":
                    self._last_result = (
                        "未登录:labs.google 没有有效的 NextAuth 会话"
                        "(页面被重定向到 Google 登录页,或仍是匿名落地页),"
                        "请先在管理台“登录窗口”里完成一次性登录"
                    )
                else:
                    self._last_result = (
                        f"未能确认登录态(落点 {url[:100] or '未知'}),请检查网络/代理后重试"
                    )
                result["reason"] = self._last_result
                result["error"] = self._last_result if state != "needs_login" else ""
                debug_logger.log_warning(
                    f"[CredentialKeeper] {self._last_result} (url={url[:120]})"
                )
                await self._maybe_close_after_cycle()
                return result

            token = await self._resolve_token(token_id)
            if token is None:
                self._last_result = "提取到凭证,但库中没有可用 Token 可写入"
                result["reason"] = self._last_result
                result["success"] = True
                await self._maybe_close_after_cycle()
                return result

            # 拿到 ST 还不够:必须先用纯 HTTP 验证它能换到可用的 AT,
            # 否则把失效 ST 写进库会让 token_manager 刷新失败并禁用 Token。
            source = "browser"
            verify = await self._verify_st(session_token)
            if not verify.get("ok"):
                # 两条自续期路径互为备份:浏览器里的会话可能已失效,而协议刷新/插件
                # 可能刚往库里写了更新的 ST——回退到库里的 ST 再验一次,可用就同步进 profile。
                browser_st = session_token
                db_st = str(getattr(token, "st", "") or "").strip()
                if db_st and db_st != browser_st:
                    db_verify = await self._verify_st(db_st)
                    if db_verify.get("ok"):
                        session_token = db_st
                        verify = db_verify
                        source = "db"
                        result["profile_resynced"] = await self._apply_st_to_profile(
                            db_st, google_cookies
                        )
                        refreshed_cookies = extract_google_cookies(await self._read_cookies())
                        google_cookies = refreshed_cookies or google_cookies
                        # 报告字段要跟着回退后的真实值走,否则会把浏览器那份失效 ST 的长度
                        # 当成结果上报(实测踩过)。
                        result["session_token_found"] = True
                        result["session_token_length"] = len(session_token)
                        result["google_cookie_count"] = len(google_cookies)
                        debug_logger.log_info(
                            f"[CredentialKeeper] Token {token.id}: 浏览器会话已失效,"
                            "已回退到库里的 ST 并同步进 profile"
                        )

            result["st_verified"] = bool(verify.get("ok"))
            result["verify_detail"] = verify.get("detail") or ""
            result["credits"] = verify.get("credits")
            result["st_source"] = source
            if not verify.get("ok"):
                self._login_state = "needs_login"
                result["login_state"] = "needs_login"
                self._last_result = (
                    "浏览器与库里的会话 Cookie 都已失效、换不到可用的 AT"
                    f"({verify.get('detail')});请在“登录窗口”里重新登录 Google"
                )
                result["reason"] = self._last_result
                debug_logger.log_warning(f"[CredentialKeeper] {self._last_result}")
                await self._maybe_close_after_cycle()
                return result

            should_write = self._auto_write() if write_db is None else bool(write_db)
            if not should_write:
                self._last_result = "提取成功(未写库)"
                result["success"] = True
                result["token_id"] = int(getattr(token, "id", 0) or 0)
                await self._maybe_close_after_cycle()
                return result

            updates: Dict[str, Any] = {"st": session_token}
            if google_cookies:
                # 与库里已有的那份合并(只增不减):本轮采集可能不完整,直接覆盖会把
                # 已验证可用的账号 Cookie 打坏。
                merged_text = merge_google_cookie_text(
                    getattr(token, "google_cookies", "") or "", google_cookies
                )
                updates["google_cookies"] = merged_text
                result["google_cookie_total"] = len(_parse_google_cookie_pairs(merged_text))
            try:
                await self._db.update_token(int(token.id), **updates)
            except Exception as exc:
                self._last_error = f"写入数据库失败: {type(exc).__name__}: {str(exc)[:160]}"
                self._last_result = self._last_error
                result["error"] = self._last_error
                debug_logger.log_error(f"[CredentialKeeper] {self._last_error}")
                await self._maybe_close_after_cycle()
                return result

            result["token_id"] = int(token.id)
            result["wrote_db"] = True
            debug_logger.log_info(
                f"[CredentialKeeper] Token {token.id}: 已从浏览器提取并写库 "
                f"(ST {len(session_token)} 字符, 本轮采集 Google Cookie {len(google_cookies)} 项, "
                f"合并后 {result.get('google_cookie_total', len(google_cookies))} 项, 来源={source})"
            )

            # ST 写库后立刻换 AT,把整条链路走通
            at_ok = None
            try:
                manager = self._token_manager
                if manager is None:
                    from ..main import token_manager as manager  # type: ignore
                at_ok = bool(await manager._refresh_at(int(token.id)))
            except Exception as exc:
                result["at_error"] = model_error(exc)

            # 回灌:刚提取到的账号 Cookie 立刻交给纯 HTTP 协议刷新路径,
            # 不必等最多 refresh_interval_minutes 分钟后的下一次调度
            if google_cookies and bool(getattr(config, "credential_keeper_push_cookies_to_protocol", True)):
                result["cookie_sync"] = await self._push_cookies_to_protocol(
                    token, google_cookies, session_token
                )

            result["at_refreshed"] = at_ok
            result["success"] = True
            self._refresh_count += 1
            self._last_success_at = _now_iso()
            self._login_state = "logged_in"
            sync = result.get("cookie_sync") or {}
            sync_bits: List[str] = []
            if sync.get("cookie_health"):
                sync_bits.append(f"Cookie 体检: {sync.get('cookie_health')}")
            proto = sync.get("protocol") or {}
            if proto:
                sync_bits.append(
                    "协议刷新: " + ("成功" if proto.get("ok") else f"未成功({str(proto.get('detail'))[:60]})")
                )
            if sync.get("profile_resynced"):
                sync_bits.append("profile 已同步协议新 ST")
            sync_text = ("；" + "，".join(sync_bits)) if sync_bits else ""
            self._last_result = (
                f"提取并写库成功(ST {len(session_token)} 字符, 来源={source}, "
                f"Google Cookie 本轮采集 {len(google_cookies)} 项/合并后 "
                f"{result.get('google_cookie_total', len(google_cookies))} 项, "
                f"AT 刷新: {at_ok}){sync_text}"
            )
            debug_logger.log_info(
                f"[CredentialKeeper] Token {token.id}: 自持刷新完成, 耗时 {time.monotonic() - started:.1f}s"
            )
            await self._maybe_close_after_cycle()
            return result

    async def _maybe_close_after_cycle(self) -> None:
        if not self._hold_open:
            await self.close()

    # ------------------------------------------------------------------ 登录窗口

    async def open_login_window(self, url: Optional[str] = None, *, hold: bool = True) -> Dict[str, Any]:
        """打开(并保持)登录窗口,供管理台通过截图/输入转发完成一次性登录。"""
        self._hold_open = bool(hold)
        page = await self._ensure_browser()
        target = str(url or "").strip() or DEFAULT_SIGNIN_URL
        try:
            await page.goto(target, wait_until="domcontentloaded", timeout=self._nav_timeout_ms())
        except Exception as exc:
            debug_logger.log_warning(
                f"[CredentialKeeper] 打开登录页时导航中断({type(exc).__name__}),按当前页面继续"
            )
        try:
            await page.wait_for_timeout(1500)
            self._current_url = str(page.url or "")
        except Exception:
            pass
        cookies = await self._read_cookies()
        self._login_state = classify_login_state(self._current_url, cookies)
        self._last_result = (
            f"登录窗口已打开({self._login_state}): {self._current_url[:120]}"
        )
        debug_logger.log_info(f"[CredentialKeeper] 登录窗口已打开: {self._current_url[:160]}")
        return self.status()

    async def stop_login_window(self) -> Dict[str, Any]:
        self._hold_open = False
        await self.close()
        self._last_result = "登录窗口已关闭(profile 已保留)"
        return self.status()

    # ------------------------------------------------------------------ 远程控制

    async def _activate(self, page) -> None:
        """把目标页提到最前。有头模式下多页签/弹窗会让输入事件落到别的页,导致“点了没反应”。"""
        try:
            await page.bring_to_front()
        except Exception:
            pass

    async def screenshot(self, *, quality: int = 55) -> bytes:
        page = self._require_browser()
        quality = max(20, min(90, int(quality)))
        # 非激活页在部分情况下会截图失败(Unable to capture screenshot),统一先提上来
        await self._activate(page)
        return await page.screenshot(type="jpeg", quality=quality)

    async def probe_point(self, x: int, y: int) -> Dict[str, Any]:
        """点击前在页内打点:命中哪个元素、页面是否可见/有焦点。

        日志里看到“命中 = null”或“可见性 = hidden”就能直接定位为什么点了没反应。
        """
        page = self._require_browser()
        script = """([x, y]) => {
            const describe = (node) => {
                if (!node) return '';
                const tag = (node.tagName || '').toLowerCase();
                const id = node.id ? '#' + node.id : '';
                const cls = (typeof node.className === 'string' && node.className)
                    ? '.' + node.className.trim().split(/\\s+/).slice(0, 2).join('.') : '';
                const text = String(node.innerText || node.getAttribute('aria-label') || '').trim().slice(0, 40);
                return tag + id + cls + (text ? ' “' + text + '”' : '');
            };
            const el = document.elementFromPoint(x, y);
            return {
                hit: describe(el),
                visibility: document.visibilityState,
                focused: document.hasFocus(),
                active: describe(document.activeElement),
                viewport: window.innerWidth + 'x' + window.innerHeight,
                scroll: window.scrollX + ',' + window.scrollY,
                url: location.href,
            };
        }"""
        try:
            data = await page.evaluate(script, [int(x), int(y)])
            return dict(data or {})
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {str(exc)[:140]}"}

    async def click(self, x: int, y: int, *, double: bool = False) -> Dict[str, Any]:
        page = self._require_browser()
        # 有头模式下窗口不一定在前台,先激活再发指针事件,避免点击落在未激活的窗口上
        await self._activate(page)
        probe = await self.probe_point(x, y)
        await page.mouse.move(int(x), int(y))
        await page.mouse.click(int(x), int(y), click_count=2 if double else 1)
        try:
            await page.wait_for_timeout(400)
        except Exception:
            pass
        after = await self._page_state(page)
        # 「命中对了、页面没变化」= 点击到了元素但页面不响应(例如被浏览器原生模态窗口挡住)
        url_changed = str(after.get("url") or "") != str(probe.get("url") or "")
        # 管理台点不动时靠这行日志判断“请求到没到、坐标是什么、点在哪个元素上、页面动没动”
        debug_logger.log_info(
            f"[CredentialKeeper] 转发点击 ({int(x)}, {int(y)})"
            f"{' 双击' if double else ''} → 命中={probe.get('hit') or probe.get('error') or 'null'} | "
            f"可见性={probe.get('visibility')} 焦点={probe.get('focused')} "
            f"活动元素={probe.get('active')} | 页面{'已变化' if url_changed else '未变化'} "
            f"| {str(after.get('url') or '')[:110]}"
        )
        return {**probe, "after": after, "url_changed": url_changed}

    async def move(self, x: int, y: int) -> None:
        page = self._require_browser()
        await page.mouse.move(int(x), int(y))

    async def type_text(self, text: str, *, enter: bool = False) -> None:
        page = self._require_browser()
        await self._activate(page)
        await page.keyboard.type(str(text), delay=30)
        if enter:
            await page.keyboard.press("Enter")
        debug_logger.log_info(
            f"[CredentialKeeper] 转发输入 {len(str(text))} 字(enter={enter}) → "
            f"{str(getattr(page, 'url', '') or '')[:120]}"
        )

    async def _page_state(self, page) -> Dict[str, Any]:
        """页面当前状态:焦点元素、可见性、URL。按键/点击前后各取一次,差别就是有没有生效。"""
        script = """() => {
            const describe = (node) => {
                if (!node) return '';
                if (node === document.body) return 'body';
                const tag = (node.tagName || '').toLowerCase();
                const id = node.id ? '#' + node.id : '';
                const text = String(node.innerText || node.getAttribute('aria-label') || '').trim().slice(0, 40);
                return tag + id + (text ? ' “' + text + '”' : '');
            };
            return {
                active: describe(document.activeElement),
                visibility: document.visibilityState,
                focused: document.hasFocus(),
                url: location.href,
                title: String(document.title || '').slice(0, 60),
            };
        }"""
        try:
            return dict(await page.evaluate(script) or {})
        except Exception as exc:
            return {"error": f"页面无响应 {type(exc).__name__}: {str(exc)[:120]}"}

    async def press(self, key: str) -> Dict[str, Any]:
        """转发按键,并回报按键前后焦点元素——“Tab 切不动焦”时这行最关键。"""
        page = self._require_browser()
        await self._activate(page)
        before = await self._page_state(page)
        await page.keyboard.press(str(key))
        try:
            await page.wait_for_timeout(150)
        except Exception:
            pass
        after = await self._page_state(page)
        debug_logger.log_info(
            f"[CredentialKeeper] 转发按键 {key} | 焦点前 {before.get('active')} → 后 {after.get('active')} "
            f"| {str(after.get('url') or '')[:110]}"
        )
        return {"key": str(key), "before": before, "after": after}

    async def scroll(self, dy: int) -> None:
        page = self._require_browser()
        await page.mouse.wheel(0, int(dy))

    async def navigate(self, url: str) -> Dict[str, Any]:
        target = str(url or "").strip()
        if not target:
            raise ValueError("url 不能为空")
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        current = await self._goto(target, settle_ms=1200)
        self._login_state = classify_login_state(current, await self._read_cookies())
        self._last_result = f"已跳转({self._login_state}): {current[:120]}"
        return {"url": current, "login_state": self._login_state}

    # ------------------------------------------------------------------ profile

    async def reset_profile(self) -> Dict[str, Any]:
        """把当前 profile 目录整体挪到一旁(不删除),下次启动会得到全新登录态。"""
        await self.close()
        profile = Path(self._profile_dir())
        backup = profile.with_name(f"{profile.name}.bak-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
        moved = False
        try:
            if profile.exists():
                profile.rename(backup)
                moved = True
        except Exception as exc:
            # 跨设备/被占用时退化为"清空内容"
            try:
                for child in profile.iterdir():
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink(missing_ok=True)
                moved = True
            except Exception as inner:
                self._last_error = f"重置 profile 失败: {type(inner).__name__}: {str(inner)[:160]}"
                return {"success": False, "error": self._last_error, "outer": str(exc)[:160]}
        self._login_state = "not_started"
        self._last_result = f"profile 已重置(备份: {backup.name})" if moved else "profile 为空,无需重置"
        debug_logger.log_info(f"[CredentialKeeper] {self._last_result}")
        return {"success": True, "backup": str(backup) if moved else "", "message": self._last_result}

    # ------------------------------------------------------------------ 后台循环

    def start(self, token_manager=None) -> None:
        if token_manager is not None:
            self._token_manager = token_manager
        if not self.enabled:
            debug_logger.log_info("[CredentialKeeper] 未启用,跳过后台自持刷新")
            return
        if self._task and not self._task.done():
            return
        self._stopping = False
        self._task = asyncio.create_task(self._loop())
        debug_logger.log_info(
            f"[CredentialKeeper] 后台自持刷新已启动(每 {self._interval_seconds()}s, "
            f"目标页 {self._target_url()})"
        )

    def force_start(self, token_manager=None) -> Dict[str, Any]:
        """不检查 enabled 开关直接拉起后台循环(用于现场验证/临时启用)。"""
        if token_manager is not None:
            self._token_manager = token_manager
        if self._task and not self._task.done():
            return {"started": False, "message": "后台自持刷新已在运行"}
        self._stopping = False
        self._task = asyncio.create_task(self._loop())
        debug_logger.log_info(
            f"[CredentialKeeper] 后台自持刷新已手动启动(每 {self._interval_seconds()}s)"
        )
        return {"started": True, "message": "已启动后台自持刷新"}

    async def stop(self) -> None:
        self._stopping = True
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        await self.close()

    async def _loop(self) -> None:
        delay = self._startup_delay_seconds()
        try:
            if delay > 0:
                self._next_run_ts = time.monotonic() + delay
                await asyncio.sleep(delay)
            while not self._stopping:
                try:
                    await self.refresh_now(reason="scheduled")
                except Exception as exc:
                    self._last_error = f"{type(exc).__name__}: {str(exc)[:160]}"
                    debug_logger.log_error(f"[CredentialKeeper] 周期刷新异常: {self._last_error}")
                # 未登录时用较短的间隔重试,便于用户完成登录后尽快自动生效
                wait = (
                    self._needs_login_retry_seconds()
                    if self._login_state == "needs_login"
                    else self._interval_seconds()
                )
                self._next_run_ts = time.monotonic() + wait
                await asyncio.sleep(wait)
        except asyncio.CancelledError:
            raise

    # ------------------------------------------------------------------ 状态

    def status(self) -> Dict[str, Any]:
        running = bool(self._task and not self._task.done())
        browser_open = self._live_page() is not None
        next_in: Optional[int] = None
        if running and self._next_run_ts:
            next_in = max(0, int(self._next_run_ts - time.monotonic()))
        return {
            "enabled": self.enabled,
            "running": running,
            "browser_open": browser_open,
            "hold_open": self._hold_open,
            "login_state": self._login_state,
            "current_url": self._current_url,
            "profile_dir": self._profile_dir(),
            "headless": self._headless(),
            "interval_seconds": self._interval_seconds(),
            "next_run_in_seconds": next_in,
            "last_run_at": self._last_run_at,
            "last_success_at": self._last_success_at,
            "last_result": self._last_result,
            "last_error": self._last_error,
            "last_extract": dict(self._last_extract),
            "refresh_count": self._refresh_count,
            "display": os.environ.get("DISPLAY", ""),
            "pages": self.list_pages(),
        }


credential_keeper = CredentialKeeper()
