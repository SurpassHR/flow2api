# -*- coding: utf-8 -*-
P = "/home/hr/flow2api/src/services/browser_captcha.py"
s = open(P, encoding="utf-8").read()

# --- 1) 页面顺序:轻量落地页优先,项目页仅作兜底 ---
old1 = "page_urls = [self._build_flow_project_url(project_id), LABS_URL]"
new1 = "page_urls = [LABS_URL, self._build_flow_project_url(project_id)]"
n1 = s.count(old1); s = s.replace(old1, new1)
print("页面顺序对调:", n1, "处(预期 1)")

# --- 2) 自定义段注入(f-string 双花括号,32 空格缩进)——先替换长版本 ---
old3 = "                                script.src = urls[index];"
new3 = (
    "                                try {{ if (!window.__f2aPolicy && window.trustedTypes && window.trustedTypes.createPolicy) {{ window.__f2aPolicy = window.trustedTypes.createPolicy('f2a-captcha', {{ createScriptURL: (s) => s }}); }} }} catch (e) {{}}\n"
    "                                script.src = (window.__f2aPolicy ? window.__f2aPolicy.createScriptURL(urls[index]) : urls[index]);"
)
n3 = s.count(old3); s = s.replace(old3, new3)
print("自定义段注入兼容:", n3, "处(预期 1)")

# --- 3) enterprise 段注入(普通字符串,24 空格缩进)——后替换短版本 ---
old2 = "                        script.src = urls[index];"
new2 = (
    "                        try { if (!window.__f2aPolicy && window.trustedTypes && window.trustedTypes.createPolicy) { window.__f2aPolicy = window.trustedTypes.createPolicy('f2a-captcha', { createScriptURL: (s) => s }); } } catch (e) {}\n"
    "                        script.src = (window.__f2aPolicy ? window.__f2aPolicy.createScriptURL(urls[index]) : urls[index]);"
)
n2 = s.count(old2); s = s.replace(old2, new2)
print("enterprise 段注入兼容:", n2, "处(预期 1)")

assert n1 == 1 and n3 == 1 and n2 == 1, "替换次数与预期不符,中止!"
open(P, "w", encoding="utf-8").write(s)

import py_compile
py_compile.compile(P, doraise=True)
print("补丁2完成,语法校验通过")
