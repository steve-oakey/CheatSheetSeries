---
name: java-spring-security
description: "Java/Spring Boot specific security scanning. Triggers when writing Spring Security configuration, JPA/Hibernate queries, Spring MVC controllers, Jackson ObjectMapper configuration, or Spring Boot application properties."
version: "1.0.0"
---

When you detect Java/Spring Boot code being written or modified, apply Spring-specific security checks from the OWASP Cheat Sheet Series.

Load the Java/Spring pattern files from each scanner domain:
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/injection/patterns/java-spring.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/xss/patterns/java-spring.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/config/patterns/java-spring.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/auth/patterns/java-spring.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/api/patterns/java-spring.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/supply-chain/patterns/java-spring.md`
- `${CLAUDE_PLUGIN_ROOT}/../../core/scanners/ai-security/patterns/java-spring.md`

Spring-specific checks:
- `csrf().disable()` or `csrf(csrf -> csrf.disable())` -- CSRF protection disabled
- `@CrossOrigin("*")` -- Overly permissive CORS
- `@RequestBody User user` without DTO -- Mass assignment
- `ObjectMapper.enableDefaultTyping()` -- Jackson deserialization RCE
- `createNativeQuery("..." + param)` -- SQL injection
- Missing `@Valid` on `@RequestBody` -- No input validation
- `permitAll()` on sensitive endpoints -- Missing authorization
- `@Query` with SpEL `?#{...}` -- Expression injection
- `server.error.include-stacktrace=always` -- Information disclosure
- `management.endpoints.web.exposure.include=*` -- Actuator exposure
- Plaintext passwords in `application.properties`/`application.yml`
