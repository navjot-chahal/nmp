# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Security

- Fix [CWE-338](https://cwe.mitre.org/data/definitions/338.html): Use `crypto/rand` to generate random nonce instead of `math/rand`