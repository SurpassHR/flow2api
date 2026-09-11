# -*- coding: utf-8 -*-
P = "/home/hr/flow2api/src/services/browser_captcha.py"
s = open(P, encoding="utf-8").read()

# 在 _wait_for_enterprise_ready 第一次超时的 except 里加诊断 dump
old = '''        except Exception as e:
            debug_logger.log_warning(
                f"[BrowserCaptcha] Token-{self.token_id} {label}grecaptcha 未就绪，尝试补注入脚本: "
                f"{type(e).__name__}: {str(e)[:200]}"
            )'''
new = '''        except Exception as e:
            debug_logger.log_warning(
                f"[BrowserCaptcha] Token-{self.token_id} {label}grecaptcha 未就绪，尝试补注入脚本: "
                f"{type(e).__name__}: {str(e)[:200]}"
            )
            try:
                _diag = await page.evaluate("() => ({url: location.href.slice(0,140), title: document.title.slice(0,60), grec: typeof grecaptcha, ent: (typeof grecaptcha !== 'undefined' ? typeof grecaptcha.enterprise : 'n/a'), rs: document.readyState, tt: (typeof trustedTypes !== 'undefined'), recScripts: Array.from(document.scripts).map(x => x.src || '').filter(x => x.includes('recaptcha')).slice(0,3), bodyHead: (document.body ? document.body.innerText.slice(0,120) : '').replace(/\\n+/g, ' | ')})")
                debug_logger.log_warning(f"[BrowserCaptcha] Token-{self.token_id} {label}页面诊断: {_diag}")
            except Exception as _de:
                debug_logger.log_warning(f"[BrowserCaptcha] Token-{self.token_id} {label}诊断失败: {type(_de).__name__}: {str(_de)[:150]}")'''
n = s.count(old); s = s.replace(old, new)
print("诊断日志注入:", n, "处(预期 1)")
assert n == 1, "替换失败,中止!"
open(P, "w", encoding="utf-8").write(s)
import py_compile
py_compile.compile(P, doraise=True)
print("补丁3完成")
