---
name: nodejs-express-security
description: "Node.js/Express-specific security scanning. Triggers when writing Express routes, Sequelize/Mongoose queries, Passport.js auth, EJS/Pug/Handlebars templates, JWT handling, or NestJS controllers."
version: "1.0.0"
---

When you detect Node.js/Express code being written or modified, apply Node.js-specific security checks from the OWASP Cheat Sheet Series.

Load the Node.js/Express pattern files from each scanner domain:
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/injection/patterns/nodejs-express.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/patterns/nodejs-express.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/patterns/nodejs-express.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/patterns/nodejs-express.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/patterns/nodejs-express.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/patterns/nodejs-express.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/ai-security/patterns/nodejs-express.md`

Node.js/Express-specific checks:
- `db.query("..." + req.body)` -- SQL/NoSQL injection via concatenation
- `.find(req.body)` / `$where` with user input -- MongoDB NoSQL injection
- `Object.assign({}, req.body)` / `_.merge()` -- Prototype pollution
- `child_process.exec()` with request data -- OS command injection
- `<%- %>` (EJS) / `{{{ }}}` (Handlebars) / `!= ` (Pug) -- Unescaped template output
- Missing `helmet()` middleware -- Missing security headers
- `cors()` with no options or `origin: '*'` -- Overly permissive CORS
- `express-session` with MemoryStore -- Session store not production-ready
- `jwt.decode()` without `jwt.verify()` -- JWT validation bypass
- Hardcoded `secret` in session/JWT config -- Credential exposure
- `node-serialize.unserialize()` -- Known RCE vulnerability
- `req.params.id` directly in `findById()` without ownership check -- IDOR
- Missing `express-rate-limit` on auth endpoints -- Brute force risk
- Loose version pins (`^`, `~`, `*`) in package.json -- Supply chain risk
- `eval()` / `new Function()` on LLM responses -- Insecure AI output handling
