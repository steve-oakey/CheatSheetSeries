# Supply Chain Patterns: Java / Spring Boot

## Secrets in Configuration
```
spring\.datasource\.password=(?!.*\$\{)   # Plaintext password (not env var)
spring\.datasource\.username=root
spring\.mail\.password=(?!.*\$\{)
spring\.redis\.password=(?!.*\$\{)
spring\.data\.mongodb\.password=(?!.*\$\{)
spring\.security\.oauth2\.client\..*secret=(?!.*\$\{)
jasypt\.encryptor\.password=(?!.*\$\{)
```

## Hardcoded Keys
```
SecretKeySpec\(.*\.getBytes\(\)         # Hardcoded key material
new SecretKeySpec\("
private static.*(KEY|key|Key)\s*=\s*"   # Static key constant
final String.*secret\s*=\s*"
```

## Weak Cryptography
```
Cipher\.getInstance\("DES              # Weak cipher
Cipher\.getInstance\("DESede           # Weak cipher
Cipher\.getInstance\("RC4              # Broken cipher
Cipher\.getInstance\(".*ECB            # Unsafe mode
Cipher\.getInstance\("AES"\)           # Default is ECB in some JVMs!
MessageDigest\.getInstance\("MD5"\)     # Weak hash
MessageDigest\.getInstance\("SHA-1"\)   # Weak hash
```

## Safe Cryptography
```
Cipher\.getInstance\("AES/GCM/NoPadding"  # Authenticated encryption
SecureRandom                              # CSPRNG
KeyGenerator\.getInstance\("AES"          # Proper key generation
KeyPairGenerator\.getInstance\("RSA"      # RSA key generation
```

## Google Tink / JCA Best Practices
```
# Safe: Google Tink APIs (recommended by Java_Security_Cheat_Sheet)
com\.google\.crypto\.tink               # Tink library import (safe)
KeysetHandle\.generateNew\(             # Tink key generation (safe)
Aead\.encrypt\(|Aead\.decrypt\(         # Tink authenticated encryption (safe)
HybridEncrypt\.encrypt\(                # Tink hybrid encryption (safe)
HybridDecrypt\.decrypt\(                # Tink hybrid decryption (safe)
DeterministicAead                       # Tink deterministic encryption (safe)
AeadConfig\.register\(\)               # Tink config registration (safe)

# Safe: JCA with proper mode/nonce
Cipher\.getInstance\("AES/GCM/NoPadding" # AES-GCM authenticated encryption (safe)
GCMParameterSpec\(128,                  # 128-bit auth tag for GCM (safe)
SecureRandom\(\)\.nextBytes\(.*12\)     # 96-bit (12-byte) nonce for GCM (safe)
KeyAgreement\.getInstance\("ECDH"       # ECDH key agreement (safe)
```

### Dangerous: Common JCA misconfigurations
```
Cipher\.getInstance\("AES/ECB           # ECB mode (no IV, pattern leakage)
Cipher\.getInstance\("AES"\)            # Default mode — ECB on some JVMs!
Cipher\.getInstance\("AES/CBC/PKCS5"    # CBC without HMAC (padding oracle risk)
new SecretKeySpec\(.*\.getBytes\("UTF   # Deriving key from string (no KDF)
new IvParameterSpec\(new byte\[16\]\)   # All-zero IV (unsafe)
cipher\.init\(.*new SecretKeySpec\(.*"  # Hardcoded key in init
```

## Weak RNG
```
new Random\(\)(?!.*Secure)              # java.util.Random (not crypto)
java\.util\.Random                      # Weak RNG class
ThreadLocalRandom                       # Not for crypto
```

## Dependency Scanning
```
owasp-dependency-check                  # Should be in pom.xml/build.gradle
dependency-check-maven                  # Maven plugin
org\.owasp\.dependencycheck             # Gradle plugin
```
Absence of dependency scanning plugin is a finding (RULE-SC-006).

## Missing Build Provenance and SBOM (RULE-SC-011)

### Check pom.xml / build.gradle for SBOM generation
```
cyclonedx-maven-plugin                  # CycloneDX SBOM plugin for Maven
org\.cyclonedx\.bom                     # CycloneDX Gradle plugin
spdx-maven-plugin                       # SPDX SBOM plugin for Maven
maven-gpg-plugin                        # GPG signing for Maven Central
signing\s*\{                            # Gradle signing config
jarsigner                               # JAR signing present
```
Absence of SBOM generation plugin in Java build config is a finding.

## Container Security Gaps (RULE-SC-012)

### Dangerous: Java/Spring Docker antipatterns
```
ARG.*SPRING_PROFILES|ARG.*JAVA_OPTS.*SECRET  # Secrets in build args
ENV.*SPRING_DATASOURCE_PASSWORD=        # DB password as env in image
COPY.*\.jar\s+/                         # Fat JAR without multi-stage
java.*-jar.*(?!.*--spring\.config\.additional-location)  # No external config mount
```

### Safe: Java/Spring container patterns
```
FROM.*eclipse-temurin.*AS\s+build       # Multi-stage with Temurin JDK
FROM.*eclipse-temurin.*jre              # JRE-only runtime image (good)
spring-boot:build-image                 # Spring Boot Buildpacks (good)
jib-maven-plugin|com\.google\.cloud\.tools\.jib  # Jib containerization (good)
HEALTHCHECK.*curl.*actuator/health     # Spring actuator health check
ENTRYPOINT.*java.*-Djava\.security\.egd # Secure random entropy source
```

## Build Configuration
```
<version>.*SNAPSHOT</version>           # Snapshot in release build
<version>.*LATEST</version>            # Unpinned version
```
