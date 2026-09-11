# -*- coding: utf-8 -*-
"""补丁5:打码浏览器不再注入登录 Session Token——登录 cookie 是 flow.google.com
间歇性跳转的触发器(probe7:带cookie 2/3跳转,不带 0/3),而 grecaptcha 打码是匿名执行,
不需要登录态。返回 True 保持既有控制流(浏览器照常创建)。"""
P = "/home/hr/flow2api/src/services/browser_captcha.py"
s = open(P, encoding="utf-8").read()

old = '''    async def _ensure_shared_token_binding(self, context, token_id: Optional[int]) -> bool:
        token_key, session_token, cookie_signature = await self._load_token_session_binding(token_id)
'''
new = '''    async def _ensure_shared_token_binding(self, context, token_id: Optional[int]) -> bool:
        # 本地补丁:跳过登录态绑定。带登录 cookie 打开 labs.google/fx/tools/flow 会被
        # 间歇性重定向到 flow.google.com/about(该页无 grecaptcha),导致打码必败;
        # reCAPTCHA Enterprise 打码为匿名执行,不依赖账号登录态。
        return True
        token_key, session_token, cookie_signature = await self._load_token_session_binding(token_id)
'''
n = s.count(old); s = s.replace(old, new)
print("跳过登录态绑定:", n, "处(预期 1)")
assert n == 1, "中止!"
open(P, "w", encoding="utf-8").write(s)
import py_compile
py_compile.compile(P, doraise=True)
print("补丁5完成,语法校验通过")
