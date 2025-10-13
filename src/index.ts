// src/index.ts
import type { Prisma, PrismaClient } from "@prisma/client";
import { mkKeysFromBuffer, encryptAEAD, decryptAEAD, hmacSha256, AES_KEY_LEN, HMAC_KEY_LEN } from "./crypto";
import type { EncryptorConfig, KeyProvider, FieldConfig } from "./types";

type PreparedField = FieldConfig & { model: string; field: string };

export function createPrismaEncryptor(config: EncryptorConfig) {
  if (!config || !config.fields || !config.keyProvider) throw new Error("Missing config or keyProvider");

  // normalize fields list
  const fieldsByModel = new Map<string, PreparedField[]>();
  for (const f of config.fields) {
    if (f.deterministic && !f.indexField) {
      throw new Error(`Field ${f.model}.${f.field} is deterministic but indexField is not provided.`);
    }
    const arr = fieldsByModel.get(f.model) ?? [];
    arr.push(f as PreparedField);
    fieldsByModel.set(f.model, arr);
  }

  async function getKeys() {
    // obtain encKey and hmacKey
    const main = await Promise.resolve(config.keyProvider());
    let encKey: Buffer;
    let hmacKey: Buffer;
    if (config.hmacKeyProvider) {
      encKey = Buffer.isBuffer(main) ? main : Buffer.from(String(main), "utf8");
      const hk = await Promise.resolve(config.hmacKeyProvider());
      hmacKey = Buffer.isBuffer(hk) ? hk : Buffer.from(String(hk), "utf8");
      if (encKey.length < AES_KEY_LEN || hmacKey.length < HMAC_KEY_LEN) {
        throw new Error("Provided keys are too short; need >=32 bytes for each.");
      }
      encKey = encKey.slice(0, AES_KEY_LEN);
      hmacKey = hmacKey.slice(0, HMAC_KEY_LEN);
    } else {
      const b = Buffer.isBuffer(main) ? main : Buffer.from(String(main), "utf8");
      const k = mkKeysFromBuffer(b);
      encKey = k.encKey;
      hmacKey = k.hmacKey;
    }
    return { encKey, hmacKey };
  }

  function findFieldConfig(model: string, field: string): PreparedField | undefined {
    const arr = fieldsByModel.get(model);
    if (!arr) return undefined;
    return arr.find(f => f.field === field);
  }

  // apply to a Prisma client instance
  function extendClient(client: PrismaClient) {
    // $use middleware
    client.$use(async (params, next) => {
      // only act on models we know
      const model = (params.model as string) || undefined;
      if (!model || !fieldsByModel.has(model)) {
        // still need to call next, and then maybe decrypt results if they contain encrypted fields via find/findMany?
        const result = await next(params);
        // decrypt result rows if applicable
        return tryDecryptResult(result, model);
      }

      const keys = await getKeys();
      const encKey = keys.encKey;
      const hmacKey = keys.hmacKey;

      // Intercept create and update and upsert: encrypt outgoing fields
      if (params.action === "create" || params.action === "update" || params.action === "upsert") {
        // handle data payload
        const data = params.args?.data;
        if (data) {
          await encryptDataForModel(model, data, encKey, hmacKey);
        }
      }

      // For findUnique/findFirst/findMany we call next then decrypt the returned rows.
      const result = await next(params);
      return tryDecryptResult(result, model, encKey, hmacKey);
    });

    return client;
  }

  async function encryptDataForModel(model: string, data: any, encKey: Buffer, hmacKey: Buffer) {
    const fields = fieldsByModel.get(model) || [];
    for (const f of fields) {
      const val = data[f.field];
      // For nested updates / create, Prisma allows objects like { set: value } in update
      // support common shapes
      const extractPlain = (v: any) => {
        if (v === null || v === undefined) return v;
        if (typeof v === "object" && "set" in v) return v.set;
        return v;
      };
      const setEncrypted = (enc: string | null) => {
        if (typeof val === "object" && "set" in val) {
          data[f.field].set = enc;
        } else {
          data[f.field] = enc;
        }
      };

      const plain = extractPlain(val);
      if (plain === null || plain === undefined) {
        // if nulls allowed and deterministic index required, clear index too
        if (f.deterministic && f.indexField) {
          data[f.indexField] = null;
        }
        setEncrypted(null);
        continue;
      }

      const enc = encryptAEAD(encKey, String(plain));
      setEncrypted(enc);

      if (f.deterministic && f.indexField) {
        const token = hmacSha256(hmacKey, String(plain));
        // set index field on same data payload
        data[f.indexField] = token;
      }
    }
  }

  function tryDecryptResult(result: any, model?: string, encKey?: Buffer, hmacKey?: Buffer) {
    // If no model known or no keys, attempt best-effort decrypt if present — but encryption requires keys.
    // If encKey undefined, return result as-is.
    if (!model || !fieldsByModel.has(model) || !encKey) return result;

    const fields = fieldsByModel.get(model)!;

    function decryptRow(row: any) {
      if (!row || typeof row !== "object") return row;
      for (const f of fields) {
        const ct = row[f.field];
        if (ct === null || ct === undefined) {
          row[f.field] = ct;
          continue;
        }
        try {
          const dec = decryptAEAD(encKey, String(ct));
          row[f.field] = dec;
        } catch (err) {
          // decrypt failed — leave as-is or optionally throw
          // keep ciphertext if decryption fails
        }
      }
      return row;
    }

    if (Array.isArray(result)) {
      return result.map(decryptRow);
    }
    // prisma's result shape: single object or { count } for count
    if (result && typeof result === "object" && ("count" in result)) {
      // ignore
      return result;
    }
    if (result && typeof result === "object") {
      return decryptRow(result);
    }
    return result;
  }

  return { extendClient };
}

export default createPrismaEncryptor;
