# -*- coding: utf-8 -*-
P = "/home/hr/flow2api/src/services/browser_captcha.py"
s = open(P, encoding="utf-8").read()
old = """                _diag = await page.evaluate("() => ({url: location.href.slice(0,140), title: document.title.slice(0,60), grec: typeof grecaptcha, ent: (typeof grecaptcha !== 'undefined' ? typeof grecaptcha.enterprise : 'n/a'), rs: document.readyState, tt: (typeof trustedTypes !== 'undefined'), recScripts: Array.from(document.scripts).map(x => x.src || '').filter(x => x.includes('recaptcha')).slice(0,3), bodyHead: (document.body ? document.body.innerText.slice(0,120) : '').replace(/\\n+/g, ' | ')})")"""
new = """                _diag = await page.evaluate("() => ({url: location.href.slice(0,140), title: document.title.slice(0,60), grec: typeof grecaptcha, ent: (typeof grecaptcha !== 'undefined' ? typeof grecaptcha.enterprise : 'n/a'), rs: document.readyState, tt: (typeof trustedTypes !== 'undefined'), recScripts: Array.from(document.scripts).map(x => x.src || '').filter(x => x.includes('recaptcha')).slice(0,3), bodyHead: (document.body ? document.body.innerText.slice(0, 150) : '')})")"""
n = s.count(old); s = s.replace(old, new)
print("诊断行修正:", n, "处(预期 1)")
assert n == 1, "中止!"
open(P, "w", encoding="utf-8").write(s)
import py_compile
py_compile.compile(P, doraise=True)
print("OK")
