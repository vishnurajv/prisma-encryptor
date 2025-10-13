// src/types.ts
import type { PrismaClient } from "@prisma/client";

export type KeyProvider = () => Promise<Buffer> | Buffer;

export type FieldConfig = {
  model: string;                 // Prisma model name e.g. "User"
  field: string;                 // field to encrypt e.g. "email"
  // optional index column where deterministic token will be stored (HMAC)
  // e.g. "email_hmac". If not provided and deterministic=true, extension will throw.
  indexField?: string;
  deterministic?: boolean;       // if true, create deterministic index token
  nullable?: boolean;            // if true, allow null values
};

export type EncryptorConfig = {
  fields: FieldConfig[];
  keyProvider: KeyProvider;      // supplies 32-byte AES key and HMAC key (see note)
  hmacKeyProvider?: KeyProvider; // optional separate HMAC key
  // If your keyProvider returns a single 64-byte buffer, we'll split:
  // first 32 bytes = AES key, next 32 = HMAC key
  // OR supply hmacKeyProvider to supply the HMAC key separately.
};
