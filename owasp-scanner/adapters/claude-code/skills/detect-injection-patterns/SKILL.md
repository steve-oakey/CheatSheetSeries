---
name: detect-injection-patterns
description: "Detects potential injection vulnerabilities when code involving database queries, process execution, XML parsing, or deserialization is being written or modified. Triggers on SQL queries, Runtime.exec(), ProcessBuilder, ObjectInputStream, XMLDecoder, DocumentBuilderFactory."
version: "1.0.0"
---

When you detect code being written or modified that involves database queries, process execution, XML parsing, or deserialization, check for injection vulnerabilities.

Read the injection rules from `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/injection/rules.md` and warn the developer about any violations.

Key patterns to watch for:
- String concatenation in SQL queries (use PreparedStatement with `?` placeholders)
- `Runtime.getRuntime().exec()` with user input (use ProcessBuilder with separate args)
- XML parsers without DTD disabled (set `disallow-doctype-decl` feature)
- `ObjectInputStream.readObject()` on untrusted data (use JSON or type-filtered deserialization)
- `XMLDecoder` usage (always unsafe, replace with JAXB)

Provide inline warnings with the specific RULE-INJ-* ID and a brief fix suggestion.
