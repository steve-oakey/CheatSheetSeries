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

## Build Configuration
```
<version>.*SNAPSHOT</version>           # Snapshot in release build
<version>.*LATEST</version>            # Unpinned version
```
