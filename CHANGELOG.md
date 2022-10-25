# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.2.0]

### Added
- Changelog
- Base Client
    - One-time authentication via code
    - JWT (ID token) verification
    - Verify credential via cloud biometric verification
    - Public-key credential authentication
    - Add base FIDO2 register/authenticate operations
- Management Client
    - Credential creation using cloud biometric proof (document verification)
    - Fido2 credential creation force-init
    - Recovery code (credential) creation
    - Public-key credential creation
    - Add base FIDO2 add-cred operation

### Changed
- Base Client
    - Private keys no longer required when there is an optional service token
- Management Client
    - Credential management operations using username or user ID

## [v0.1.0]
### Security

- Fix [CWE-338](https://cwe.mitre.org/data/definitions/338.html): Use `crypto/rand` to generate random nonce instead of `math/rand`
