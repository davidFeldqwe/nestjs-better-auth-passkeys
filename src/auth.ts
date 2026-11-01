import { passkey } from "@better-auth/passkey";
import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { twoFactor } from "better-auth/plugins";
import type { Database } from "./database/database.module.js";
import { deviceBinding } from "./device-binding/index.js";
import type { MailService } from "./mail/mail.service.js";

export function createAuth(db: Database, secret: string, port: number, mail: MailService) {
  const origin = `http://localhost:${port}`;
  return betterAuth({
    baseURL: origin,
    secret,
    database: drizzleAdapter(db, { provider: "sqlite" }),
    emailAndPassword: { enabled: true },
    user: {
      additionalFields: {
        role: {
          type: "string",
          required: false,
          defaultValue: "user",
          input: false, // clients can't set their own role at sign-up; promote admins server-side
        },
      },
    },
    plugins: [
      passkey({ rpID: "localhost", rpName: "NestJS Better Auth Passkeys Demo", origin }),
      twoFactor({
        otpOptions: {
          async sendOTP({ user, otp }) {
            await mail.sendOtp(user.email, otp);
          },
        },
      }),
      deviceBinding(),
    ],
  });
}
