import { PrismaClient } from "@prisma/client";
import createPrismaEncryptor from "prisma-encryptor";

const prisma = new PrismaClient();

const encryptor = createPrismaEncryptor({
  fields: [
    { model: "User", field: "email", indexField: "email_hmac", deterministic: true },
    { model: "User", field: "phone", indexField: "phone_hmac", deterministic: true },
    { model: "User", field: "ssn", deterministic: false }
  ],
  keyProvider: () => Buffer.from(process.env.MASTER_KEY!, "utf8")
});

encryptor.extendClient(prisma);

(async () => {
  // Standard create
  await prisma.user.create({
    data: {
      email: "alice@example.com",
      phone: "+15550001111",
      ssn: "111-22-3333"
    }
  });

  // Deterministic lookups (multiple)
  const user1 = await prisma.user.findUniqueWithHash({
    where: { email: "alice@example.com" }
  });

  const user2 = await prisma.user.findFirstWithHash({
    where: { phone: "+15550001111" }
  });

  const users = await prisma.user.findManyWithHash({
    where: { email: "alice@example.com", phone: "+15550001111" }
  });

  console.log({ user1, user2, users });
})();
