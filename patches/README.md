# 本地补丁说明(2026-09-07)

应用对象:src/services/browser_captcha.py(通过 docker-compose.headed-override.yml 挂载进容器)

| 补丁 | 作用 |
|---|---|
| patch_captcha.py | wait_for_function 改为箭头函数(绕开 Trusted Types 禁 eval);page.evaluate 双参数改单列表(Playwright Python 签名) |
| patch2.py | 打码页面顺序对调(轻量落地页优先);脚本注入加 TrustedTypes createPolicy 兜底 |
| patch3.py / patch3b.py | grecaptcha 等待超时时 dump 页面诊断信息到 logs.txt |
| patch4.py | route 拦截器:阻断打码页面向 flow.google.com 的顶层导航(该页无 grecaptcha) |
| patch5.py | 打码浏览器跳过登录态绑定——登录 cookie 是 flow.google.com 间歇性跳转的触发器(probe7:带 cookie 2/3 跳转,不带 0/3),而 reCAPTCHA 打码为匿名执行 |

注意:git pull 上游后这些修改会被覆盖/冲突,重新应用顺序:patch_captcha → patch2 → patch3b → patch4 → patch5,然后重启容器。

## patch6:SSE 心跳(2026-09-07 晚)

应用对象:src/api/routes.py

| 补丁 | 作用 |
|---|---|
| patch6-routes-heartbeat.diff | 新增 `_stream_with_sse_heartbeat`(15s 空闲发 `: keepalive` SSE 注释行,复位 Cloudflare/nginx 空闲计时器),包在 OpenAI/Gemini 两个流式端点最外层。解决 Cloudflare 免费版 ~100s 空闲切断导致 "Error in input stream" 及服务端误判客户端断开而取消生成的问题 |

重新应用:git apply patches/patch6-routes-heartbeat.diff(与 patch_captcha~patch5 互不冲突,作用于不同文件)。
