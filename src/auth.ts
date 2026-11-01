// Better Auth instance. Follows:
//  - https://www.better-auth.com/docs/installation (SQLite via better-sqlite3)
//  - https://www.better-auth.com/docs/plugins/passkey
//  - https://www.better-auth.com/docs/plugins/2fa (OTP + trusted devices)
import { betterAuth } from "better-auth";
import { twoFactor } from "better-auth/plugins";
import { passkey } from "@better-auth/passkey";
import Database from "better-sqlite3";

const PORT = Number(process.env.PORT ?? 3000);
const ORIGIN = `http://localhost:${PORT}`;

// ponytail: OTPs go to the console and an in-memory map (tests read it). Swap for email/SMS in a real app.
export const lastOtp = new Map<string, string>();

export function createAuth(dbFile = process.env.DB_FILE ?? "auth.sqlite") {
  return betterAuth({
    baseURL: ORIGIN,
    secret: process.env.BETTER_AUTH_SECRET ?? "dev-only-secret-change-me-dev-only-secret",
    database: new Database(dbFile),
    emailAndPassword: { enabled: true },
    plugins: [
      passkey({ rpID: "localhost", rpName: "NestJS Better Auth Passkeys Demo", origin: ORIGIN }),
      twoFactor({
        otpOptions: {
          async sendOTP({ user, otp }) {
            lastOtp.set(user.email, otp);
            console.log(`[2FA] OTP for ${user.email}: ${otp}`);
          },
        },
      }),
    ],
  });
}

export const auth = createAuth();
