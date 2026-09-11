# -*- coding: utf-8 -*-
P = "/home/hr/flow2api/src/services/browser_captcha.py"
s = open(P, encoding="utf-8").read()

old = '''        page_urls = [LABS_URL, self._build_flow_project_url(project_id)]
        label = f"{context_label} " if context_label else ""
'''
new = '''        page_urls = [LABS_URL, self._build_flow_project_url(project_id)]
        label = f"{context_label} " if context_label else ""

        # 防跳转:Google 会间歇性把登录用户重定向到 flow.google.com/about(该页无 grecaptcha),
        # 拦截打码页面的顶层导航,强制留在 labs.google 域
        try:
            async def _block_flow_redirect(route):
                try:
                    req = route.request
                    if req.is_navigation_request() and req.frame.parent_frame is None:
                        debug_logger.log_warning(
                            f"[BrowserCaptcha] Token-{self.token_id} {label}已拦截跳转: {req.url[:120]}"
                        )
                        await route.abort()
                    else:
                        await route.continue_()
                except Exception:
                    try:
                        await route.continue_()
                    except Exception:
                        pass
            await page.route("https://flow.google.com/**", _block_flow_redirect)
        except Exception:
            pass
'''
n = s.count(old); s = s.replace(old, new)
print("防跳转补丁:", n, "处(预期 1)")
assert n == 1, "中止!"
open(P, "w", encoding="utf-8").write(s)
import py_compile
py_compile.compile(P, doraise=True)
print("补丁4完成,语法校验通过")
