"""Configuration management for Flow2API"""
import os
import tomli
from pathlib import Path
from typing import Dict, Any, Optional

DEFAULT_YESCAPTCHA_TASK_TYPE = "RecaptchaV3TaskProxylessM1S9"
YESCAPTCHA_TASK_TYPE_OPTIONS = {
    "RecaptchaV3TaskProxyless": None,
    "RecaptchaV3TaskProxylessM1": None,
    "RecaptchaV3TaskProxylessM1S7": 0.7,
    "RecaptchaV3TaskProxylessM1S9": 0.9,
}


def normalize_yescaptcha_task_type(task_type: Optional[str]) -> str:
    normalized = (task_type or "").strip()
    if normalized in YESCAPTCHA_TASK_TYPE_OPTIONS:
        return normalized
    return DEFAULT_YESCAPTCHA_TASK_TYPE


def get_yescaptcha_min_score(task_type: Optional[str]) -> Optional[float]:
    return YESCAPTCHA_TASK_TYPE_OPTIONS.get(normalize_yescaptcha_task_type(task_type))


class Config:
    """Application configuration"""

    def __init__(self):
        self._config = self._load_config()
        self._admin_username: Optional[str] = None
        self._admin_password: Optional[str] = None

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from setting.toml, falling back to the example file."""
        config_dir = Path(__file__).parent.parent.parent / "config"
        config_path = config_dir / "setting.toml"
        fallback_path = config_dir / "setting_example.toml"

        if config_path.exists() and not config_path.is_file():
            print(
                f"[Config] 检测到 {config_path} 不是普通文件，"
                f"将回退到 {fallback_path.name}。请检查 Docker 挂载或本地配置路径。"
            )
            config_path = fallback_path
        elif not config_path.exists():
            config_path = fallback_path

        if not config_path.is_file():
            raise FileNotFoundError(
                f"配置文件不存在或不可读取: {config_path}. "
                f"请确认 config 目录下存在可用的 setting.toml 或 setting_example.toml"
            )

        with open(config_path, "rb") as f:
            return tomli.load(f)

    def reload_config(self):
        """Reload configuration from file"""
        self._config = self._load_config()

    def get_raw_config(self) -> Dict[str, Any]:
        """Get raw configuration dictionary"""
        return self._config

    @property
    def admin_username(self) -> str:
        # If admin_username is set from database, use it; otherwise fall back to config file
        if self._admin_username is not None:
            return self._admin_username
        return self._config["global"]["admin_username"]

    @admin_username.setter
    def admin_username(self, value: str):
        self._admin_username = value
        self._config["global"]["admin_username"] = value

    def set_admin_username_from_db(self, username: str):
        """Set admin username from database"""
        self._admin_username = username

    # Flow2API specific properties
    @property
    def flow_labs_base_url(self) -> str:
        """Google Labs base URL for project management"""
        return self._config["flow"]["labs_base_url"]

    @property
    def flow_api_base_url(self) -> str:
        """Google AI Sandbox API base URL for generation"""
        return self._config["flow"]["api_base_url"]

    @property
    def flow_timeout(self) -> int:
        timeout = self._config.get("flow", {}).get("timeout", 120)
        try:
            return max(5, int(timeout))
        except Exception:
            return 120

    @property
    def flow_max_retries(self) -> int:
        retries = self._config.get("flow", {}).get("max_retries", 3)
        try:
            return max(1, int(retries))
        except Exception:
            return 3

    def set_flow_max_retries(self, retries: int):
        """Set flow max retries"""
        if "flow" not in self._config:
            self._config["flow"] = {}
        try:
            normalized = max(1, int(retries))
        except Exception:
            normalized = 3
        self._config["flow"]["max_retries"] = normalized

    @property
    def flow_image_request_timeout(self) -> int:
        """图片生成单次 HTTP 请求超时(秒)。"""
        default_timeout = min(self.flow_timeout, 40)
        timeout = self._config.get("flow", {}).get(
            "image_request_timeout",
            default_timeout
        )
        try:
            return max(5, int(timeout))
        except Exception:
            return self.flow_timeout

    @property
    def flow_image_timeout_retry_count(self) -> int:
        """图片生成遇到网络超时时的快速重试次数。"""
        retry_count = self._config.get("flow", {}).get("image_timeout_retry_count", 1)
        try:
            return max(0, min(3, int(retry_count)))
        except Exception:
            return 1

    @property
    def flow_image_timeout_retry_delay(self) -> float:
        """图片生成网络超时重试前等待秒数。"""
        delay = self._config.get("flow", {}).get("image_timeout_retry_delay", 0.8)
        try:
            return max(0.0, min(5.0, float(delay)))
        except Exception:
            return 0.8

    @property
    def flow_image_timeout_use_media_proxy_fallback(self) -> bool:
        """网络超时时是否切换媒体代理重试。"""
        return bool(
            self._config.get("flow", {}).get(
                "image_timeout_use_media_proxy_fallback",
                True
            )
        )

    @property
    def flow_image_prefer_media_proxy(self) -> bool:
        """图片生成是否优先走媒体代理链路。"""
        return bool(
            self._config.get("flow", {}).get(
                "image_prefer_media_proxy",
                False
            )
        )

    @property
    def flow_image_slot_wait_timeout(self) -> float:
        """图片硬并发槽位等待超时(秒)。"""
        timeout = self._config.get("flow", {}).get("image_slot_wait_timeout", 120)
        try:
            return max(1.0, min(600.0, float(timeout)))
        except Exception:
            return 120.0

    @property
    def flow_image_launch_soft_limit(self) -> int:
        """图片生成前置发车软并发上限(0 表示关闭软整形，仅使用硬并发)。"""
        value = self._config.get("flow", {}).get("image_launch_soft_limit", 0)
        try:
            return max(0, min(200, int(value)))
        except Exception:
            return 0

    @property
    def flow_image_launch_wait_timeout(self) -> float:
        """图片前置发车软并发等待超时(秒)。"""
        timeout = self._config.get("flow", {}).get("image_launch_wait_timeout", 180)
        try:
            return max(1.0, min(600.0, float(timeout)))
        except Exception:
            return 180.0

    @property
    def flow_image_launch_stagger_ms(self) -> int:
        """图片请求前置发车间隔(毫秒)，用于平滑同批突发。"""
        value = self._config.get("flow", {}).get("image_launch_stagger_ms", 0)
        try:
            return max(0, min(5000, int(value)))
        except Exception:
            return 0

    @property
    def flow_video_slot_wait_timeout(self) -> float:
        """视频硬并发槽位等待超时(秒)。"""
        timeout = self._config.get("flow", {}).get("video_slot_wait_timeout", 120)
        try:
            return max(1.0, min(600.0, float(timeout)))
        except Exception:
            return 120.0

    @property
    def flow_video_launch_soft_limit(self) -> int:
        """视频生成前置发车软并发上限(0 表示关闭软整形，仅使用硬并发)。"""
        value = self._config.get("flow", {}).get("video_launch_soft_limit", 0)
        try:
            return max(0, min(200, int(value)))
        except Exception:
            return 0

    @property
    def flow_video_launch_wait_timeout(self) -> float:
        """视频前置发车软并发等待超时(秒)。"""
        timeout = self._config.get("flow", {}).get("video_launch_wait_timeout", 180)
        try:
            return max(1.0, min(600.0, float(timeout)))
        except Exception:
            return 180.0

    @property
    def flow_video_launch_stagger_ms(self) -> int:
        """视频请求前置发车间隔(毫秒)，用于平滑同批突发。"""
        value = self._config.get("flow", {}).get("video_launch_stagger_ms", 0)
        try:
            return max(0, min(5000, int(value)))
        except Exception:
            return 0

    @property
    def poll_interval(self) -> float:
        return self._config["flow"]["poll_interval"]

    @property
    def max_poll_attempts(self) -> int:
        return self._config["flow"]["max_poll_attempts"]

    @property
    def server_host(self) -> str:
        return self._config["server"]["host"]

    @property
    def server_port(self) -> int:
        return self._config["server"]["port"]

    @property
    def debug_enabled(self) -> bool:
        return self._config.get("debug", {}).get("enabled", False)

    @property
    def debug_log_requests(self) -> bool:
        return self._config.get("debug", {}).get("log_requests", True)

    @property
    def debug_log_responses(self) -> bool:
        return self._config.get("debug", {}).get("log_responses", True)

    @property
    def debug_mask_token(self) -> bool:
        return self._config.get("debug", {}).get("mask_token", True)

    # Mutable properties for runtime updates
    @property
    def api_key(self) -> str:
        return self._config["global"]["api_key"]

    @api_key.setter
    def api_key(self, value: str):
        self._config["global"]["api_key"] = value

    @property
    def admin_password(self) -> str:
        # If admin_password is set from database, use it; otherwise fall back to config file
        if self._admin_password is not None:
            return self._admin_password
        return self._config["global"]["admin_password"]

    @admin_password.setter
    def admin_password(self, value: str):
        self._admin_password = value
        self._config["global"]["admin_password"] = value

    def set_admin_password_from_db(self, password: str):
        """Set admin password from database"""
        self._admin_password = password

    def set_debug_enabled(self, enabled: bool):
        """Set debug mode enabled/disabled"""
        if "debug" not in self._config:
            self._config["debug"] = {}
        self._config["debug"]["enabled"] = enabled

    @property
    def image_timeout(self) -> int:
        """Get image generation timeout in seconds"""
        return self._config.get("generation", {}).get("image_timeout", 300)

    def set_image_timeout(self, timeout: int):
        """Set image generation timeout in seconds"""
        if "generation" not in self._config:
            self._config["generation"] = {}
        self._config["generation"]["image_timeout"] = timeout

    @property
    def video_timeout(self) -> int:
        """Get video generation timeout in seconds"""
        return self._config.get("generation", {}).get("video_timeout", 1500)

    def set_video_timeout(self, timeout: int):
        """Set video generation timeout in seconds"""
        if "generation" not in self._config:
            self._config["generation"] = {}
        self._config["generation"]["video_timeout"] = timeout

    @property
    def polling_mode_enabled(self) -> bool:
        """Get polling mode enabled status."""
        return self.call_logic_mode == "polling"

    @property
    def call_logic_mode(self) -> str:
        """Get call logic mode (default or polling)."""
        call_logic = self._config.get("call_logic", {})
        mode = call_logic.get("call_mode")
        if mode in ("default", "polling"):
            return mode
        if call_logic.get("polling_mode_enabled", False):
            return "polling"
        return "default"

    def set_polling_mode_enabled(self, enabled: bool):
        """Set polling mode enabled/disabled."""
        self.set_call_logic_mode("polling" if enabled else "default")

    def set_call_logic_mode(self, mode: str):
        """Set call logic mode (default or polling)."""
        normalized = "polling" if mode == "polling" else "default"
        if "call_logic" not in self._config:
            self._config["call_logic"] = {}
        self._config["call_logic"]["call_mode"] = normalized
        self._config["call_logic"]["polling_mode_enabled"] = normalized == "polling"

    @property
    def upsample_timeout(self) -> int:
        """Get upsample (4K/2K) timeout in seconds"""
        return self._config.get("generation", {}).get("upsample_timeout", 300)

    def set_upsample_timeout(self, timeout: int):
        """Set upsample (4K/2K) timeout in seconds"""
        if "generation" not in self._config:
            self._config["generation"] = {}
        self._config["generation"]["upsample_timeout"] = timeout

    # Cache configuration
    @property
    def cache_enabled(self) -> bool:
        """Get cache enabled status"""
        return self._config.get("cache", {}).get("enabled", False)

    def set_cache_enabled(self, enabled: bool):
        """Set cache enabled status"""
        if "cache" not in self._config:
            self._config["cache"] = {}
        self._config["cache"]["enabled"] = enabled

    @property
    def cache_timeout(self) -> int:
        """Get cache timeout in seconds"""
        return self._config.get("cache", {}).get("timeout", 7200)

    def set_cache_timeout(self, timeout: int):
        """Set cache timeout in seconds"""
        if "cache" not in self._config:
            self._config["cache"] = {}
        self._config["cache"]["timeout"] = timeout

    @property
    def cache_base_url(self) -> str:
        """Get cache base URL"""
        return self._config.get("cache", {}).get("base_url", "")

    def set_cache_base_url(self, base_url: str):
        """Set cache base URL"""
        if "cache" not in self._config:
            self._config["cache"] = {}
        self._config["cache"]["base_url"] = base_url

    # Captcha configuration
    @property
    def captcha_method(self) -> str:
        """Get captcha method"""
        return self._config.get("captcha", {}).get("captcha_method", "yescaptcha")

    def set_captcha_method(self, method: str):
        """Set captcha method"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["captcha_method"] = method

    @property
    def browser_launch_background(self) -> bool:
        """有头浏览器打码是否默认后台启动，避免抢占前台窗口。"""
        return self._config.get("captcha", {}).get("browser_launch_background", True)

    def set_browser_launch_background(self, enabled: bool):
        """设置有头浏览器打码是否后台启动。"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["browser_launch_background"] = bool(enabled)

    @property
    def browser_headless(self) -> bool:
        """browser 模式是否使用无头浏览器，内存紧张时开启可省 100-150MB。"""
        return bool(self._config.get("captcha", {}).get("browser_headless", False))

    def set_browser_headless(self, enabled: bool):
        """设置 browser 模式是否使用无头浏览器。"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["browser_headless"] = bool(enabled)

    @property
    def browser_count(self) -> int:
        """浏览器打码实例数量，browser/personal 模式共用。"""
        value = self._config.get("captcha", {}).get("browser_count", 1)
        try:
            return max(1, min(20, int(value)))
        except Exception:
            return 1

    def set_browser_count(self, value: int):
        """设置浏览器打码实例数量。"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["browser_count"] = max(1, min(20, int(value)))

    @property
    def browser_recaptcha_settle_seconds(self) -> float:
        """有头打码在 reload/clr 就绪后的额外等待秒数。"""
        value = self._config.get("captcha", {}).get("browser_recaptcha_settle_seconds", 3.0)
        try:
            return max(0.0, min(10.0, float(value)))
        except Exception:
            return 3.0

    @property
    def browser_captcha_submit_in_browser(self) -> bool:
        """browser 模式是否在浏览器内提交生成请求。

        True(默认):优先在打码浏览器里 fetch,拿不到 grecaptcha 时自动回退 HTTP 提交。
        False:始终走服务端 HTTP 提交(打码仍由内置浏览器完成)。
        """
        return bool(self._config.get("captcha", {}).get("browser_captcha_submit_in_browser", True))

    @property
    def browser_idle_ttl_seconds(self) -> int:
        value = self._config.get("captcha", {}).get("browser_idle_ttl_seconds", 600)
        try:
            return max(60, int(value))
        except Exception:
            return 600

    @property
    def browser_captcha_max_retries(self) -> int:
        """browser 模式单次打码最大重试次数。"""
        value = self._config.get("captcha", {}).get("browser_captcha_max_retries", 5)
        try:
            return max(1, min(20, int(value)))
        except Exception:
            return 5

    @property
    def browser_captcha_generation_retries(self) -> int:
        """生成接口因 reCAPTCHA 评估失败时允许的总重试次数。

        每次重试都要重新打码(数十秒到两分钟),默认值不宜大:上下文类失败重试也过不了。
        """
        value = self._config.get("captcha", {}).get("browser_captcha_generation_retries", 3)
        try:
            return max(1, min(20, int(value)))
        except Exception:
            return 3

    @property
    def browser_mask_headless_ua(self) -> bool:
        """无头浏览器是否把 UA 里的 ``HeadlessChrome`` 标记抹掉。

        默认 True:上游会把 HeadlessChrome 当成自动化流量,导致 reCAPTCHA 评估失败
        (PUBLIC_ERROR_UNUSUAL_ACTIVITY)。
        """
        return bool(self._config.get("captcha", {}).get("browser_mask_headless_ua", True))

    @property
    def browser_recaptcha_failure_recycle(self) -> bool:
        """上游报 reCAPTCHA evaluation failed 时是否重建打码浏览器。

        默认 False:token 被拒是签发上下文问题,重建浏览器只会白耗 1-2 分钟。
        """
        return bool(self._config.get("captcha", {}).get("browser_recaptcha_failure_recycle", False))

    @property
    def browser_environment_patch(self) -> bool:
        """是否向打码浏览器注入 navigator/screen/window 环境补齐脚本。

        默认 False(2026-09-11 实测结论):该脚本用 Object.defineProperty 覆盖
        Navigator.prototype 等原生属性,reCAPTCHA Enterprise 会将其识别为篡改/
        自动化特征,即使 token 签发在正确的 labs.google 上也会被上游以
        PUBLIC_ERROR_UNUSUAL_ACTIVITY 拒绝。关闭后真实生图恢复正常。
        navigator.webdriver 仍由单独的轻量覆盖脚本处理,不受此开关影响。
        """
        return bool(self._config.get("captcha", {}).get("browser_environment_patch", False))

    @property
    def browser_bind_login_state(self) -> bool:
        """browser 模式是否把账号登录态(ST + Google cookies)注入打码浏览器。

        默认 True:flow.google.com 的应用页只对登录态开放,匿名只能拿到无 grecaptcha 的
        /about,会导致打码 token 被上游以 PUBLIC_ERROR_UNUSUAL_ACTIVITY 拒绝。
        """
        return bool(self._config.get("captcha", {}).get("browser_bind_login_state", True))

    @property
    def browser_use_keeper_profile(self) -> bool:
        """打码浏览器是否直接复用凭证浏览器(keeper)的持久 profile。

        默认 False。开启后打码与 keeper 共用同一个 profile(单 jar),登录态与
        cookie 同意态天然一致,不再依赖“临时 context + 注入快照”。
        打码前会先关闭 keeper 浏览器以释放 Chromium profile 单例锁。
        """
        return bool(self._config.get("captcha", {}).get("use_keeper_profile", False))

    @property
    def browser_captcha_solve_timeout(self) -> int:
        """单次打码硬超时(秒)，超时强制回收浏览器防止悬挂。"""
        value = self._config.get("captcha", {}).get("browser_captcha_solve_timeout", 150)
        try:
            return max(30, int(value))
        except Exception:
            return 150

    @property
    def browser_captcha_bootstrap_url(self) -> str:
        """打码 token 获取用的中性页面(无 CSP 限制,可注入 enterprise.js)。

        必须是 https://labs.google/ 一类与提交请求 Origin/Referer 同源的页面:
        reCAPTCHA Enterprise 会校验 token 的签发主机名,签发在 www.google.com 上会
        被上游以 PUBLIC_ERROR_UNUSUAL_ACTIVITY 拒绝(2026-09-11 实测)。
        """
        value = self._config.get("captcha", {}).get("browser_captcha_bootstrap_url", "https://labs.google/")
        return str(value or "").strip()

    @property
    def google_cookie_health_check_enabled(self) -> bool:
        """是否启用 Google Cookies(账号态)健康巡检。

        默认 True:失效的 google_cookies 会造成一连串误导性假象(ST→AT 仍能返回用户、
        应用页被 302 到 accounts.google.com、协议刷新只报“Google 拒绝登录”、
        上游 401/403),因此需要主动给出一致结论并在后台告警。
        """
        return bool(self._config.get("captcha", {}).get("google_cookie_health_check_enabled", True))

    @property
    def google_cookie_health_check_ttl_seconds(self) -> int:
        """Google Cookies 健康结论的缓存时长(秒)，到期后重新探测。"""
        value = self._config.get("captcha", {}).get("google_cookie_health_check_ttl_seconds", 600)
        try:
            return max(30, int(value))
        except Exception:
            return 600

    @property
    def google_cookie_health_check_timeout_seconds(self) -> int:
        """单次 Google Cookies 探测请求超时(秒)。"""
        value = self._config.get("captcha", {}).get("google_cookie_health_check_timeout_seconds", 12)
        try:
            return max(3, int(value))
        except Exception:
            return 12

    @property
    def google_cookie_health_probe_url(self) -> str:
        """Google Cookies 探测地址(默认需登录才能访问的 myaccount.google.com)。"""
        value = self._config.get("captcha", {}).get(
            "google_cookie_health_probe_url", "https://myaccount.google.com/"
        )
        return str(value or "").strip() or "https://myaccount.google.com/"

    @property
    def google_cookie_health_sweep_interval_seconds(self) -> int:
        """后台巡检间隔(秒)。"""
        value = self._config.get("captcha", {}).get("google_cookie_health_sweep_interval_seconds", 300)
        try:
            return max(30, int(value))
        except Exception:
            return 300

    # ---------------------------------------------------------------- 凭证浏览器
    # 服务器自持登录态:用持久 profile 的 Chromium 自己维持并提取 ST/账号 Cookie,
    # 使服务器不必依赖本地浏览器插件持续推送。详见 services/credential_keeper.py。

    @property
    def credential_keeper_enabled(self) -> bool:
        """是否启用服务器自持凭证浏览器。

        默认 False:它会额外拉起一个 Chromium,只适合确实想摆脱本地插件的部署。
        """
        return bool(self._config.get("credential_keeper", {}).get("enabled", False))

    @property
    def credential_keeper_interval_seconds(self) -> int:
        """后台自持刷新间隔(秒)。"""
        value = self._config.get("credential_keeper", {}).get("interval_seconds", 1800)
        try:
            return max(120, int(value))
        except Exception:
            return 1800

    @property
    def credential_keeper_startup_delay_seconds(self) -> int:
        """启动后延迟多久才做第一次自持刷新(秒),避开启动期的打码预热。"""
        value = self._config.get("credential_keeper", {}).get("startup_delay_seconds", 30)
        try:
            return max(0, int(value))
        except Exception:
            return 30

    @property
    def credential_keeper_headless(self) -> bool:
        """凭证浏览器是否无头运行。

        默认 False:有头(配合 DISPLAY/Xvfb)才能让管理台的截图转发真正用于完成登录。
        """
        return bool(self._config.get("credential_keeper", {}).get("headless", False))

    @property
    def credential_keeper_profile_dir(self) -> str:
        """持久 profile 目录。指向 bind-mount 目录即可在容器重建后保留登录态。"""
        return str(self._config.get("credential_keeper", {}).get("profile_dir", "") or "").strip()

    @property
    def credential_keeper_target_url(self) -> str:
        """用于判定登录态并读取 cookie 的页面。"""
        value = self._config.get("credential_keeper", {}).get(
            "target_url", "https://labs.google/fx/tools/flow"
        )
        return str(value or "").strip()

    @property
    def credential_keeper_auto_write(self) -> bool:
        """提取到凭证后是否自动写库(关闭则只提取、不覆盖现有 Token)。"""
        return bool(self._config.get("credential_keeper", {}).get("auto_write", True))

    @property
    def credential_keeper_token_id(self) -> int:
        """凭证写回的目标 Token ID;0 表示自动选择第一个启用中的 Token。"""
        value = self._config.get("credential_keeper", {}).get("token_id", 0)
        try:
            return max(0, int(value))
        except Exception:
            return 0

    @property
    def credential_keeper_remote_control_enabled(self) -> bool:
        """是否启用管理台的截图/输入转发(服务器上直接完成一次性登录)。"""
        return bool(self._config.get("credential_keeper", {}).get("remote_control_enabled", True))

    @property
    def credential_keeper_disable_passkey(self) -> bool:
        """是否让凭证浏览器的页面用不到通行密钥(passkey)。

        默认 True:服务器上的 Chromium 没有任何可用认证器,页面一旦真的发起
        WebAuthn 请求,Chrome 会弹出的原生选择窗口在 Xvfb 里无人可点,而且它是模态的,
        页面从此收不到鼠标/键盘事件,登录就永远卡在“Verifying it's you…”。
        关掉后 Google 会直接退回密码/验证码等可用方式。
        """
        return bool(self._config.get("credential_keeper", {}).get("disable_passkey", True))

    @property
    def credential_keeper_skip_when_captcha_busy(self) -> bool:
        """打码任务进行中时跳过本轮自持刷新,避免小内存机器上两个 Chromium 抢资源。"""
        return bool(self._config.get("credential_keeper", {}).get("skip_when_captcha_busy", True))

    @property
    def credential_keeper_hydrate_from_db(self) -> bool:
        """启动时是否把库里的 ST/账号 Cookie 注入持久 profile(两者互为容错)。

        默认 True:profile 丢失时用库补齐;库里失效时由 profile 重新提取覆盖。
        注入不代表会话有效,真正写库前仍会 ST→AT 验证。
        """
        return bool(self._config.get("credential_keeper", {}).get("hydrate_from_db", True))

    @property
    def credential_keeper_push_cookies_to_protocol(self) -> bool:
        """提取到账号 Cookie 后是否立即回灌给 protocol_mode 的协议刷新路径。

        默认 True:让“浏览器自持”与“纯 HTTP 协议自续期”互为备份——
        新鲜 Cookie 一到就立刻重算 Cookie 体检并马上跑一次协议刷新,
        而不是等最多 refresh_interval_minutes 分钟后的下一次调度。
        """
        return bool(
            self._config.get("credential_keeper", {}).get("push_cookies_to_protocol", True)
        )

    @property
    def credential_keeper_harvest_account_cookies(self) -> bool:
        """每轮提取前是否先让浏览器去 accounts.google.com/myaccount 走一趟。

        默认 True:__Secure-*PSIDTS(会话轮转时间戳)、__Secure-STRP、OSID 这些
        账号态 Cookie 是访问时下发/轮转的;不续期就会慢慢变旧,出现"浏览器里
        还登录着、拉平成 HTTP 头却被 302 回登录页"的假象。
        """
        return bool(
            self._config.get("credential_keeper", {}).get("harvest_account_cookies", True)
        )

    @property
    def credential_keeper_needs_login_retry_seconds(self) -> int:
        """未登录状态下的重试间隔(秒),用于用户完成登录后尽快自动生效。"""
        value = self._config.get("credential_keeper", {}).get("needs_login_retry_seconds", 300)
        try:
            return max(60, int(value))
        except Exception:
            return 300

    @property
    def credential_keeper_min_free_mb(self) -> int:
        """可用内存低于该值(MB)时跳过本轮自持刷新;0 表示不限制。"""
        value = self._config.get("credential_keeper", {}).get("min_free_mb", 150)
        try:
            return max(0, int(value))
        except Exception:
            return 150

    @property
    def credential_keeper_nav_timeout_seconds(self) -> int:
        """凭证浏览器单次导航超时(秒)。"""
        value = self._config.get("credential_keeper", {}).get("nav_timeout_seconds", 45)
        try:
            return max(10, int(value))
        except Exception:
            return 45

    @property
    def browser_captcha_max_busy_seconds(self) -> int:
        """打码 busy 超过该秒数时，idle reaper 强制回收浏览器兜底。"""
        value = self._config.get("captcha", {}).get("browser_captcha_max_busy_seconds", 900)
        try:
            return max(300, int(value))
        except Exception:
            return 900

    @property
    def personal_max_resident_tabs(self) -> int:
        """内置浏览器打码单实例共享标签页上限"""
        value = self._config.get("captcha", {}).get("personal_max_resident_tabs", 5)
        try:
            return max(1, min(50, int(value)))  # 限制在1-50之间
        except Exception:
            return 5

    @property
    def personal_project_pool_size(self) -> int:
        """单个 Token 默认维护的项目池数量，仅影响项目轮换。"""
        value = self._config.get("captcha", {}).get("personal_project_pool_size", 4)
        try:
            return max(1, min(50, int(value)))
        except Exception:
            return 4

    @property
    def personal_idle_tab_ttl_seconds(self) -> int:
        """内置浏览器打码标签页空闲超时(秒)"""
        value = self._config.get("captcha", {}).get("personal_idle_tab_ttl_seconds", 600)
        try:
            return max(60, int(value))
        except Exception:
            return 600

    @property
    def personal_headless(self) -> bool:
        """personal 内置浏览器是否强制无头；默认按有头模式运行。"""
        env_value = os.getenv("PERSONAL_BROWSER_HEADLESS")
        if env_value is not None:
            return str(env_value).strip().lower() in {"1", "true", "yes", "on"}
        return bool(self._config.get("captcha", {}).get("personal_headless", False))

    def set_personal_max_resident_tabs(self, value: int):
        """设置内置浏览器打码单实例共享标签页上限"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["personal_max_resident_tabs"] = max(1, min(50, int(value)))

    def set_personal_project_pool_size(self, value: int):
        """设置单个 Token 默认维护的项目池数量，仅影响项目轮换"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["personal_project_pool_size"] = max(1, min(50, int(value)))

    def set_personal_idle_tab_ttl_seconds(self, value: int):
        """设置内置浏览器打码标签页空闲超时(秒)"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["personal_idle_tab_ttl_seconds"] = max(60, int(value))

    @property
    def browser_personal_fresh_restart_every_n_solves(self) -> int:
        """内置浏览器成功打码多少次后使用全新 profile 重启，0 表示禁用。"""
        value = self._config.get("captcha", {}).get("browser_personal_fresh_restart_every_n_solves", 10)
        try:
            return max(0, int(value))
        except Exception:
            return 10

    def set_browser_personal_fresh_restart_every_n_solves(self, value: int):
        """设置内置浏览器 fresh profile 轮换阈值。"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["browser_personal_fresh_restart_every_n_solves"] = max(0, int(value))

    @property
    def yescaptcha_api_key(self) -> str:
        """Get YesCaptcha API key"""
        return self._config.get("captcha", {}).get("yescaptcha_api_key", "")

    def set_yescaptcha_api_key(self, api_key: str):
        """Set YesCaptcha API key"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["yescaptcha_api_key"] = api_key

    @property
    def yescaptcha_base_url(self) -> str:
        """Get YesCaptcha base URL"""
        return self._config.get("captcha", {}).get("yescaptcha_base_url", "https://api.yescaptcha.com")

    def set_yescaptcha_base_url(self, base_url: str):
        """Set YesCaptcha base URL"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["yescaptcha_base_url"] = base_url

    @property
    def yescaptcha_task_type(self) -> str:
        """Get YesCaptcha reCAPTCHA V3 task type"""
        return normalize_yescaptcha_task_type(
            self._config.get("captcha", {}).get(
                "yescaptcha_task_type",
                DEFAULT_YESCAPTCHA_TASK_TYPE,
            )
        )

    def set_yescaptcha_task_type(self, task_type: str):
        """Set YesCaptcha reCAPTCHA V3 task type"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["yescaptcha_task_type"] = normalize_yescaptcha_task_type(task_type)

    @property
    def capmonster_api_key(self) -> str:
        """Get CapMonster API key"""
        return self._config.get("captcha", {}).get("capmonster_api_key", "")

    def set_capmonster_api_key(self, api_key: str):
        """Set CapMonster API key"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["capmonster_api_key"] = api_key

    @property
    def capmonster_base_url(self) -> str:
        """Get CapMonster base URL"""
        return self._config.get("captcha", {}).get("capmonster_base_url", "https://api.capmonster.cloud")

    def set_capmonster_base_url(self, base_url: str):
        """Set CapMonster base URL"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["capmonster_base_url"] = base_url

    @property
    def ezcaptcha_api_key(self) -> str:
        """Get EzCaptcha API key"""
        return self._config.get("captcha", {}).get("ezcaptcha_api_key", "")

    def set_ezcaptcha_api_key(self, api_key: str):
        """Set EzCaptcha API key"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["ezcaptcha_api_key"] = api_key

    @property
    def ezcaptcha_base_url(self) -> str:
        """Get EzCaptcha base URL"""
        return self._config.get("captcha", {}).get("ezcaptcha_base_url", "https://api.ez-captcha.com")

    def set_ezcaptcha_base_url(self, base_url: str):
        """Set EzCaptcha base URL"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["ezcaptcha_base_url"] = base_url

    @property
    def capsolver_api_key(self) -> str:
        """Get CapSolver API key"""
        return self._config.get("captcha", {}).get("capsolver_api_key", "")

    def set_capsolver_api_key(self, api_key: str):
        """Set CapSolver API key"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["capsolver_api_key"] = api_key

    @property
    def capsolver_base_url(self) -> str:
        """Get CapSolver base URL"""
        return self._config.get("captcha", {}).get("capsolver_base_url", "https://api.capsolver.com")

    def set_capsolver_base_url(self, base_url: str):
        """Set CapSolver base URL"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["capsolver_base_url"] = base_url

    @property
    def remote_browser_base_url(self) -> str:
        """Get remote browser captcha service base URL"""
        return self._config.get("captcha", {}).get("remote_browser_base_url", "")

    def set_remote_browser_base_url(self, base_url: str):
        """Set remote browser captcha service base URL"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["remote_browser_base_url"] = (base_url or "").strip()

    @property
    def remote_browser_api_key(self) -> str:
        """Get remote browser captcha service API key"""
        return self._config.get("captcha", {}).get("remote_browser_api_key", "")

    def set_remote_browser_api_key(self, api_key: str):
        """Set remote browser captcha service API key"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        self._config["captcha"]["remote_browser_api_key"] = (api_key or "").strip()

    @property
    def remote_browser_timeout(self) -> int:
        """Get remote browser captcha request timeout (seconds)"""
        timeout = self._config.get("captcha", {}).get("remote_browser_timeout", 60)
        try:
            return max(5, int(timeout))
        except Exception:
            return 60

    def set_remote_browser_timeout(self, timeout: int):
        """Set remote browser captcha request timeout (seconds)"""
        if "captcha" not in self._config:
            self._config["captcha"] = {}
        try:
            normalized = max(5, int(timeout))
        except Exception:
            normalized = 60
        self._config["captcha"]["remote_browser_timeout"] = normalized


# Global config instance
config = Config()
