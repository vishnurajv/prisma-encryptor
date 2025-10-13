// src/index.ts
import type { PrismaClient } from "@prisma/client";
import { mkKeysFromBuffer, encryptAEAD, decryptAEAD, hmacSha256 } from "./crypto";
import type { EncryptorConfig, FieldConfig } from "./types";

/**
 * Prisma Encryptor Extension
 * - Encrypts/decrypts configured fields automatically
 * - Supports deterministic lookups via HMAC-based index fields
 * - Adds model helpers: findUniqueWithHash(), findFirstWithHash(), findManyWithHash()
 */

type PreparedField = FieldConfig & { model: string; field: string };

export function createPrismaEncryptor(config: EncryptorConfig) {
  if (!config?.fields?.length || !config.keyProvider)
    throw new Error("Invalid configuration: fields[] and keyProvider are required");

  const fieldsByModel = new Map<string, PreparedField[]>();

  for (const f of config.fields) {
    if (f.deterministic && !f.indexField)
      throw new Error(`Field ${f.model}.${f.field} is deterministic but indexField is missing.`);
    const list = fieldsByModel.get(f.model) ?? [];
    list.push(f as PreparedField);
    fieldsByModel.set(f.model, list);
  }

  async function getKeys() {
    const provided = await Promise.resolve(config.keyProvider());
    const buf = Buffer.isBuffer(provided) ? provided : Buffer.from(String(provided), "utf8");
    return mkKeysFromBuffer(buf);
  }

  /** Encrypt fields before writing to DB */
  async function encryptDataForModel(model: string, data: any, encKey: Buffer, hmacKey: Buffer) {
    const fields = fieldsByModel.get(model) || [];
    for (const f of fields) {
      const val = data[f.field];
      if (val === null || val === undefined) {
        if (f.deterministic && f.indexField) data[f.indexField] = null;
        continue;
      }

      data[f.field] = encryptAEAD(encKey, String(val));
      if (f.deterministic && f.indexField)
        data[f.indexField] = hmacSha256(hmacKey, String(val));
    }
  }

  /** Decrypt results */
  function decryptResult(result: any, model: string, encKey: Buffer) {
    if (!result || typeof result !== "object") return result;
    const fields = fieldsByModel.get(model) || [];
    const decryptRow = (row: any) => {
      if (!row) return row;
      for (const f of fields) {
        const ct = row[f.field];
        if (typeof ct === "string") {
          try {
            row[f.field] = decryptAEAD(encKey, ct);
          } catch {
            // ignore failed decrypt
          }
        }
      }
      return row;
    };
    return Array.isArray(result) ? result.map(decryptRow) : decryptRow(result);
  }

  /** Converts where clause with plaintext deterministic fields → hashed index fields */
  function transformWhereClause(where: Record<string, any>, fields: PreparedField[], hmacKey: Buffer) {
    const patched: Record<string, any> = { ...where };
    for (const f of fields) {
      if (f.deterministic && f.indexField && where[f.field] !== undefined) {
        const val = where[f.field];
        if (val !== null && val !== undefined) {
          patched[f.indexField] = hmacSha256(hmacKey, String(val));
        }
        delete patched[f.field];
      }
    }
    return patched;
  }

  /** Adds dynamic model helpers */
  async function attachModelHelpers(client: PrismaClient) {
    const { encKey, hmacKey } = await getKeys();

    for (const [modelName, fields] of fieldsByModel.entries()) {
      const model = (client as any)[modelName.toLowerCase()];
      if (!model) continue;

      /** findUniqueWithHash */
      model.findUniqueWithHash = async (args: any) => {
        const patchedWhere = transformWhereClause(args.where || {}, fields, hmacKey);
        const result = await model.findUnique({ ...args, where: patchedWhere });
        return decryptResult(result, modelName, encKey);
      };

      /** findFirstWithHash */
      model.findFirstWithHash = async (args: any) => {
        const patchedWhere = transformWhereClause(args.where || {}, fields, hmacKey);
        const result = await model.findFirst({ ...args, where: patchedWhere });
        return decryptResult(result, modelName, encKey);
      };

      /** findManyWithHash */
      model.findManyWithHash = async (args: any) => {
        const patchedWhere = transformWhereClause(args.where || {}, fields, hmacKey);
        const result = await model.findMany({ ...args, where: patchedWhere });
        return decryptResult(result, modelName, encKey);
      };
    }
  }

  /** Core middleware registration */
  function extendClient(client: PrismaClient) {
    client.$use(async (params, next) => {
      const model = params.model as string;
      if (!model || !fieldsByModel.has(model)) return next(params);

      const { encKey, hmacKey } = await getKeys();

      // Encrypt writes
      if (["create", "update", "upsert"].includes(params.action)) {
        const data = params.args?.data;
        if (data) await encryptDataForModel(model, data, encKey, hmacKey);
      }

      const result = await next(params);

      // Decrypt reads
      if (["findUnique", "findFirst", "findMany"].includes(params.action))
        return decryptResult(result, model, encKey);

      return result;
    });

    // Attach model helpers
    attachModelHelpers(client).catch(err =>
      console.error("Failed to attach model helpers:", err)
    );

    return client;
  }

  return { extendClient };
}

export default createPrismaEncryptor;
