// example/usage.ts
import { PrismaClient } from "@prisma/client";
import createPrismaEncryptor from "prisma-encryptor"; // local path in dev
import fs from "fs";
import path from "path";

const prisma = new PrismaClient();

// simple keyProvider - in prod use KMS or environment variable vault
const keyBuf = Buffer.from(process.env.APP_MASTER_KEY || "change_me_make_it_64_bytes_long_for_demo................................", "utf8");

const encryptor = createPrismaEncryptor({
  fields: [
    { model: "User", field: "email", indexField: "email_hmac", deterministic: true },
    { model: "User", field: "ssn", deterministic: false }, // just encrypted, no index
  ],
  keyProvider: () => keyBuf
});

encryptor.extendClient(prisma);

async function run() {
  await prisma.user.create({
    data: {
      name: "Alice",
      email: "alice@example.com",
      ssn: "111-22-3333"
    }
  });

  // find by deterministic token — you must compute token client-side (or store given token).
  const token = require("crypto").createHmac("sha256", keyBuf).update("alice@example.com").digest("hex");

  // you can now query by email_hmac
  const user = await prisma.user.findUnique({
    where: { email_hmac: token }
  });

  console.log("Decrypted user:", user); // user.email and user.ssn will be plaintext
}

run();
