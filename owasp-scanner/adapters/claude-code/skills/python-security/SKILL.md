---
name: python-security
description: "Python-specific security scanning (Django, Flask, FastAPI). Triggers when writing Python code with Django ORM queries, Flask request handling, FastAPI endpoints, Jinja2 templates, SQLAlchemy queries, or Python-specific auth patterns."
version: "1.0.0"
---

When you detect Python code being written or modified, apply Python-specific security checks from the OWASP Cheat Sheet Series.

Load the Python pattern files from each scanner domain:
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/injection/patterns/python.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/patterns/python.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/patterns/python.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/patterns/python.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/patterns/python.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/patterns/python.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/ai-security/patterns/python.md`

Python-specific checks:
- `.raw()` or `cursor.execute()` with f-strings/% formatting -- SQL injection
- `render_template_string()` with request data -- SSTI / XSS
- `|safe` or `mark_safe()` with user-controlled data -- XSS
- `DEBUG = True` in production settings -- Information disclosure
- `SECRET_KEY` hardcoded (not from `os.environ`) -- Credential exposure
- `ALLOWED_HOSTS = ['*']` or `CORS_ALLOW_ALL_ORIGINS = True` -- Overly permissive config
- `@csrf_exempt` decorator -- CSRF protection disabled
- `pickle.load()` / `yaml.load()` without SafeLoader -- Unsafe deserialization
- `subprocess.call(shell=True)` with user input -- OS command injection
- `os.path.join()` with request data -- Path traversal
- Missing `@login_required` / `Depends(get_current_user)` on sensitive endpoints -- Missing auth
- `hashlib.md5()` / `hashlib.sha1()` for passwords -- Weak hashing
- Unpinned dependencies in `requirements.txt` -- Supply chain risk
- `exec()` / `eval()` on LLM responses -- Insecure AI output handling
