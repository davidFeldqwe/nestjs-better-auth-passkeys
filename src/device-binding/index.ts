import { APIError, createAuthEndpoint, sessionMiddleware } from "better-auth/api";
import { expireCookie, setSessionCookie } from "better-auth/cookies";
import type { BetterAuthPlugin } from "better-auth";
import { z } from "zod";

const NONCE_TTL_MS = 2 * 60 * 1000;
const MODEL = "deviceBinding";

// ponytail: one nonce row in the shared verification table, 2 minute TTL, no attempt counter.
function nonceIdentifier(userId: string, deviceId: string) {
  return `device-binding:${userId}:${deviceId}`;
}

const jwkSchema = z.object({
  kty: z.string(),
  crv: z.string(),
  x: z.string().min(1),
  y: z.string().min(1),
  d: z.string().optional(),
});

function reject(status: "BAD_REQUEST" | "UNAUTHORIZED" | "NOT_FOUND", message: string, code: string): never {
  throw APIError.from(status, { message, code });
}

/** EC P-256 public JWK only. A `d` field is the private scalar and must not be stored. */
function publicP256Jwk(input: z.infer<typeof jwkSchema>): { kty: "EC"; crv: "P-256"; x: string; y: string } {
  if (input.d !== undefined) reject("BAD_REQUEST", "Public key must not include private field d", "PRIVATE_KEY_REJECTED");
  if (input.kty !== "EC" || input.crv !== "P-256") {
    reject("BAD_REQUEST", "Only EC P-256 public keys are accepted", "UNSUPPORTED_KEY");
  }
  return { kty: "EC", crv: "P-256", x: input.x, y: input.y };
}

async function importVerifyKey(jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }) {
  try {
    return await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  } catch {
    reject("BAD_REQUEST", "Public key could not be imported", "UNSUPPORTED_KEY");
  }
}

type AuthCtx = {
  body: { deviceId?: string; signature?: string };
  context: {
    secret: string;
    session: { user: { id: string } };
    authCookies: { dontRememberToken: { name: string } };
    createAuthCookie: (name: string) => Parameters<typeof expireCookie>[1];
    internalAdapter: {
      findVerificationValue: (identifier: string) => Promise<{ value: string; expiresAt: Date | string } | null>;
      consumeVerificationValue: (identifier: string) => Promise<{ value: string } | null>;
      createVerificationValue: (data: { value: string; identifier: string; expiresAt: Date }) => Promise<unknown>;
      deleteVerificationByIdentifier: (identifier: string) => Promise<unknown>;
      findUserById: (id: string) => Promise<Parameters<typeof setSessionCookie>[1]["user"] | null>;
      createSession: (userId: string, dontRememberMe: boolean) => Promise<Parameters<typeof setSessionCookie>[1]["session"] | null>;
    };
    adapter: {
      create: (args: { model: string; data: Record<string, unknown> }) => Promise<{ id: string }>;
      findOne: (args: { model: string; where: { field: string; value: unknown }[] }) => Promise<DeviceRow | null>;
      findMany: (args: { model: string; where: { field: string; value: unknown }[] }) => Promise<DeviceRow[]>;
      update: (args: { model: string; where: { field: string; value: unknown }[]; update: Record<string, unknown> }) => Promise<unknown>;
    };
  };
  getSignedCookie: (name: string, secret: string) => Promise<string | null | false | undefined>;
  json: (body: unknown) => unknown;
};

type DeviceRow = {
  id: string;
  userId: string;
  publicKey: string;
  name: string;
  createdAt: Date | string;
  lastUsedAt?: Date | string | null;
  revokedAt?: Date | string | null;
};

async function pendingTwoFactor(ctx: AuthCtx) {
  // Cookie name matches TWO_FACTOR_COOKIE_NAME in
  // node_modules/better-auth/dist/plugins/two-factor/constant.mjs.
  const cookie = ctx.context.createAuthCookie("two_factor");
  const identifier = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
  if (!identifier) reject("UNAUTHORIZED", "No pending two-factor sign-in", "NO_PENDING_TWO_FACTOR");
  const verification = await ctx.context.internalAdapter.findVerificationValue(identifier);
  if (!verification) reject("UNAUTHORIZED", "No pending two-factor sign-in", "NO_PENDING_TWO_FACTOR");
  const user = await ctx.context.internalAdapter.findUserById(verification.value);
  if (!user) reject("UNAUTHORIZED", "No pending two-factor sign-in", "NO_PENDING_TWO_FACTOR");
  return { user, identifier };
}

async function ownActiveDevice(ctx: AuthCtx, userId: string, deviceId: string) {
  const device = await ctx.context.adapter.findOne({
    model: MODEL,
    where: [{ field: "id", value: deviceId }],
  });
  if (!device || device.userId !== userId || device.revokedAt) {
    reject("BAD_REQUEST", "Unknown or revoked device", "UNKNOWN_DEVICE");
  }
  return device;
}

/**
 * Finish a pending 2FA sign-in the way verify-otp does after a good code.
 * Mirrors `verifyTwoFactor().valid` in
 * node_modules/better-auth/dist/plugins/two-factor/verify-two-factor.mjs.
 * That helper is not exported from the public two-factor plugin.
 */
async function finishPendingTwoFactor(ctx: AuthCtx, user: NonNullable<Awaited<ReturnType<AuthCtx["context"]["internalAdapter"]["findUserById"]>>>, identifier: string) {
  const twoFactorCookie = ctx.context.createAuthCookie("two_factor");
  const dontRememberMe = await ctx.getSignedCookie(ctx.context.authCookies.dontRememberToken.name, ctx.context.secret);
  const consumed = await ctx.context.internalAdapter.consumeVerificationValue(identifier);
  if (!consumed || consumed.value !== user.id) {
    expireCookie(ctx as Parameters<typeof expireCookie>[0], twoFactorCookie);
    reject("UNAUTHORIZED", "Invalid two factor cookie", "INVALID_TWO_FACTOR_COOKIE");
  }
  const session = await ctx.context.internalAdapter.createSession(consumed.value, !!dontRememberMe);
  if (!session) reject("BAD_REQUEST", "failed to create session", "FAILED_TO_CREATE_SESSION");
  // The value is the endpoint context; AuthCtx only names the fields this file reads.
  await setSessionCookie(ctx as Parameters<typeof setSessionCookie>[0], { session, user });
  expireCookie(ctx as Parameters<typeof expireCookie>[0], twoFactorCookie);
  return ctx.json({ token: session.token, user });
}

export function deviceBinding(): BetterAuthPlugin {
  return {
    id: "device-binding",
    schema: {
      deviceBinding: {
        fields: {
          userId: {
            type: "string",
            required: true,
            references: { model: "user", field: "id", onDelete: "cascade" },
            index: true,
          },
          publicKey: { type: "string", required: true },
          name: { type: "string", required: true },
          createdAt: { type: "date", required: true },
          lastUsedAt: { type: "date", required: false },
          revokedAt: { type: "date", required: false },
        },
      },
    },
    endpoints: {
      registerDevice: createAuthEndpoint(
        "/device-binding/register",
        {
          method: "POST",
          body: z.object({ publicKey: jwkSchema, name: z.string().min(1).max(64) }),
          use: [sessionMiddleware],
        },
        async (ctx) => {
          const jwk = publicP256Jwk(ctx.body.publicKey);
          await importVerifyKey(jwk);
          const row = await ctx.context.adapter.create({
            model: MODEL,
            data: {
              userId: ctx.context.session.user.id,
              publicKey: JSON.stringify(jwk),
              name: ctx.body.name,
              createdAt: new Date(),
            },
          });
          return ctx.json({ deviceId: row.id });
        },
      ),
      listDevices: createAuthEndpoint(
        "/device-binding/list",
        { method: "GET", use: [sessionMiddleware] },
        async (ctx) => {
          const rows = await ctx.context.adapter.findMany<DeviceRow>({
            model: MODEL,
            where: [{ field: "userId", value: ctx.context.session.user.id }],
          });
          return ctx.json({
            devices: rows
              .filter((row) => !row.revokedAt)
              .map((row) => ({
                id: row.id,
                name: row.name,
                createdAt: row.createdAt,
                lastUsedAt: row.lastUsedAt ?? null,
              })),
          });
        },
      ),
      revokeDevice: createAuthEndpoint(
        "/device-binding/revoke",
        {
          method: "POST",
          body: z.object({ deviceId: z.string().min(1) }),
          use: [sessionMiddleware],
        },
        async (ctx) => {
          const device = await ctx.context.adapter.findOne<DeviceRow>({
            model: MODEL,
            where: [{ field: "id", value: ctx.body.deviceId }],
          });
          if (!device || device.userId !== ctx.context.session.user.id) {
            reject("NOT_FOUND", "Device not found", "DEVICE_NOT_FOUND");
          }
          await ctx.context.adapter.update({
            model: MODEL,
            where: [{ field: "id", value: device.id }],
            update: { revokedAt: new Date() },
          });
          return ctx.json({ revoked: true });
        },
      ),
      challengeDevice: createAuthEndpoint(
        "/device-binding/challenge",
        {
          method: "POST",
          body: z.object({ deviceId: z.string().min(1) }),
        },
        async (ctx) => {
          const pending = await pendingTwoFactor(ctx as AuthCtx);
          await ownActiveDevice(ctx as AuthCtx, pending.user.id, ctx.body.deviceId);
          const bytes = new Uint8Array(32);
          crypto.getRandomValues(bytes);
          const nonce = Buffer.from(bytes).toString("base64url");
          const identifier = nonceIdentifier(pending.user.id, ctx.body.deviceId);
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(identifier);
          await ctx.context.internalAdapter.createVerificationValue({
            value: nonce,
            identifier,
            expiresAt: new Date(Date.now() + NONCE_TTL_MS),
          });
          return ctx.json({ nonce });
        },
      ),
      verifyDevice: createAuthEndpoint(
        "/device-binding/verify",
        {
          method: "POST",
          body: z.object({ deviceId: z.string().min(1), signature: z.string().min(1) }),
        },
        async (ctx) => {
          const authCtx = ctx as AuthCtx;
          const pending = await pendingTwoFactor(authCtx);
          const device = await ownActiveDevice(authCtx, pending.user.id, ctx.body.deviceId);
          const identifier = nonceIdentifier(pending.user.id, device.id);
          const row = await ctx.context.internalAdapter.findVerificationValue(identifier);
          if (!row || new Date(row.expiresAt).getTime() <= Date.now()) {
            if (row) await ctx.context.internalAdapter.consumeVerificationValue(identifier);
            reject("UNAUTHORIZED", "Challenge expired or already used", "CHALLENGE_EXPIRED");
          }
          const nonce = row.value;
          let ok = false;
          try {
            const key = await importVerifyKey(JSON.parse(device.publicKey));
            const data = Buffer.from(nonce, "base64url");
            const signature = Buffer.from(ctx.body.signature, "base64url");
            ok = await crypto.subtle.verify(
              { name: "ECDSA", hash: "SHA-256" },
              key,
              new Uint8Array(signature),
              new Uint8Array(data),
            );
          } catch {
            ok = false;
          }
          if (!ok) {
            // ponytail: a bad signature does not consume the nonce, so the same challenge can be retried until it expires.
            reject("UNAUTHORIZED", "Invalid device signature", "INVALID_SIGNATURE");
          }
          const consumed = await ctx.context.internalAdapter.consumeVerificationValue(identifier);
          if (!consumed || consumed.value !== nonce) {
            reject("UNAUTHORIZED", "Challenge expired or already used", "CHALLENGE_EXPIRED");
          }
          await ctx.context.adapter.update({
            model: MODEL,
            where: [{ field: "id", value: device.id }],
            update: { lastUsedAt: new Date() },
          });
          return finishPendingTwoFactor(authCtx, pending.user, pending.identifier);
        },
      ),
    },
  };
}
