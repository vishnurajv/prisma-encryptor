# prisma-encryptor

Prisma middleware/extension for **transparent encryption** of database fields.

Supports:
- AES-256-GCM non-deterministic encryption
- Deterministic lookups using HMAC index fields

## Install

```bash
npm install prisma-encryptor