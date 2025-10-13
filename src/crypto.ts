// src/crypto.ts
import crypto from "crypto";

export const AES_KEY_LEN = 32;
export const HMAC_KEY_LEN = 32;
export const IV_LEN = 12; // 96-bit recommended for GCM

export function mkKeysFromBuffer(buf: Buffer): { encKey: Buffer; hmacKey: Buffer } {
  if (buf.length === AES_KEY_LEN) {
    throw new Error("Need HMAC key too (either return 64 bytes or provide hmacKeyProvider).");
  }
  if (buf.length === AES_KEY_LEN + HMAC_KEY_LEN) {
    return { encKey: buf.slice(0, AES_KEY_LEN), hmacKey: buf.slice(AES_KEY_LEN) };
  }
  if (buf.length >= AES_KEY_LEN) {
    // If user passed >=32 bytes, we derive using HKDF.
    const encKey = buf.slice(0, AES_KEY_LEN);
    const hmacKey = crypto.createHmac("sha256", buf).update("hmac-key-derivation").digest().slice(0, HMAC_KEY_LEN);
    return { encKey, hmacKey };
  }
  throw new Error("Key buffer too short");
}

export function encryptAEAD(encKey: Buffer, plaintext: Buffer | string): string {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv("aes-256-gcm", encKey, iv);
  const ptBuf = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
  const ciphertext = Buffer.concat([cipher.update(ptBuf), cipher.final()]);
  const tag = cipher.getAuthTag();
  // store iv | tag | ciphertext in base64 (iv + tag + ciphertext)
  return Buffer.concat([iv, tag, ciphertext]).toString("base64");
}

export function decryptAEAD(encKey: Buffer, tokenB64: string): string {
  const raw = Buffer.from(tokenB64, "base64");
  const iv = raw.slice(0, IV_LEN);
  const tag = raw.slice(IV_LEN, IV_LEN + 16);
  const ciphertext = raw.slice(IV_LEN + 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", encKey, iv);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return pt.toString("utf8");
}

export function hmacSha256(hmacKey: Buffer, value: string): string {
  // returns hex or base64 token — prefer hex for DB index
  return crypto.createHmac("sha256", hmacKey).update(value, "utf8").digest("hex");
}
