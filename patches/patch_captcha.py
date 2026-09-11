# -*- coding: utf-8 -*-
import re

P = "/home/hr/flow2api/src/services/browser_captcha.py"
s = open(P, encoding="utf-8").read()
orig = s

# --- 1a) 三元形式的 wait_expression(自定义打码段, ~1894) ---
JS_ENT = "() => (typeof grecaptcha !== 'undefined' && typeof grecaptcha.enterprise !== 'undefined' && typeof grecaptcha.enterprise.execute === 'function')"
JS_PLAIN = "() => (typeof grecaptcha !== 'undefined' && typeof grecaptcha.execute === 'function')"
pat_ternary = re.compile(
    r"( *)wait_expression = \(\n"
    r"\s*\"typeof grecaptcha !== 'undefined' && typeof grecaptcha\.enterprise !== 'undefined' && \"\n"
    r"\s*\"typeof grecaptcha\.enterprise\.execute === 'function'\"\n"
    r"\s*\) if enterprise else \(\n"
    r"\s*\"typeof grecaptcha !== 'undefined' && typeof grecaptcha\.execute === 'function'\"\n"
    r"\s*\)"
)
def _repl_t(m):
    ind = m.group(1)
    return (ind + 'wait_expression = "' + JS_ENT + '" if enterprise else "' + JS_PLAIN + '"')
s, n_ternary = pat_ternary.subn(_repl_t, s)
print("三元 wait_expression 替换:", n_ternary, "处(预期 1)")

# --- 1b) 简单形式的 wait_expression(enterprise 段, ~2094) ---
pat_simple = re.compile(
    r"( *)wait_expression = \(\n"
    r"\s*\"typeof grecaptcha !== 'undefined' && \"\n"
    r"\s*\"typeof grecaptcha\.enterprise !== 'undefined' && \"\n"
    r"\s*\"typeof grecaptcha\.enterprise\.execute === 'function'\"\n"
    r"\s*\)"
)
def _repl_s(m):
    ind = m.group(1)
    return ind + 'wait_expression = "' + JS_ENT + '"'
s, n_simple = pat_simple.subn(_repl_s, s)
print("简单 wait_expression 替换:", n_simple, "处(预期 1)")

# --- 2) 自定义段:evaluate 双参数 -> 单列表参数 ---
old2 = '""", f"{primary_host}/{script_path}?render={website_key}", f"{secondary_host}/{script_path}?render={website_key}")'
new2 = '""", [f"{primary_host}/{script_path}?render={website_key}", f"{secondary_host}/{script_path}?render={website_key}"])'
n2 = s.count(old2); s = s.replace(old2, new2)
print("自定义段 evaluate 参数修复:", n2, "处(预期 1)")

# --- 3) 自定义段 JS 头(f-string 双花括号版) ---
old3 = "(primaryUrl, secondaryUrl) => {{"
new3 = "([primaryUrl, secondaryUrl]) => {{"
n3 = s.count(old3); s = s.replace(old3, new3)
print("自定义段 JS 头修复:", n3, "处(预期 1)")

# --- 4) enterprise 段 JS 头(普通字符串版) ---
old4 = "(primaryUrl, secondaryUrl) => {"
new4 = "([primaryUrl, secondaryUrl]) => {"
n4 = s.count(old4); s = s.replace(old4, new4)
print("enterprise 段 JS 头修复:", n4, "处(预期 1)")

# --- 5) enterprise 段 evaluate 双参数 -> 单列表参数 ---
old5 = '''f"{primary_host}/recaptcha/enterprise.js?render={website_key}",
                f"{secondary_host}/recaptcha/enterprise.js?render={website_key}",
            )'''
new5 = '''[
                    f"{primary_host}/recaptcha/enterprise.js?render={website_key}",
                    f"{secondary_host}/recaptcha/enterprise.js?render={website_key}",
                ],
            )'''
n5 = s.count(old5); s = s.replace(old5, new5)
print("enterprise 段 evaluate 参数修复:", n5, "处(预期 1)")

assert n_ternary == 1 and n_simple == 1 and n2 == 1 and n3 == 1 and n4 == 1 and n5 == 1, "替换次数与预期不符,中止!"
open(P, "w", encoding="utf-8").write(s)

import py_compile
py_compile.compile(P, doraise=True)
print("补丁完成,语法校验通过")
