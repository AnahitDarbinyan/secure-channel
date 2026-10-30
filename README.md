# Secure Inline Communication Channel

## Project Overview

This project aims to develop a secure inline communication channel between two computers through two intermediate devices.

**Network architecture:**

PC1 → Device1 → Device2 → PC2

## Project Objectives

- Establish a secure session between Device1 and Device2.
- Implement X25519 Diffie–Hellman key exchange.
- Derive encryption keys using HKDF.
- Encrypt TCP payloads using AES-256-GCM.
- Authenticate and decrypt received payloads.
- Preserve and correctly process network packet headers.

## Technologies

- Kali Linux ARM64
- C programming language
- GCC compiler
- OpenSSL
- Linux networking tools

## Project Structure

- `src/` — Source code
- `include/` — Header files
- `tests/` — Test programs
- `screenshots/` — Project evidence
- `docs/` — Documentation

## Development Progress

- [x] X25519 key generation test
- [x] X25519 shared-secret agreement test
- [ ] AES-256-GCM encryption and decryption
- [ ] HKDF key derivation
- [ ] Device1 and Device2 communication
- [ ] TCP packet processing
- [ ] End-to-end testing

**Status:** Under development as an academic project.