// Server-side flow tests against the real Nest app + Better Auth on an in-memory SQLite DB.
// No WebAuthn ceremony is faked: we test option generation and the trusted-device logic only.
import "reflect-metadata";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { INestApplication } from "@nestjs/common";

process.env.DB_FILE = ":memory:";
process.env.BETTER_AUTH_SECRET = "test-secret-test-secret-test-secret";
const { NestFactory } = await import("@nestjs/core");
const { AppModule } = await import("../src/app.module.js");
const { configureApp } = await import("../src/configure-app.js");
const { assertAuthSecret } = await import("../src/config.js");
const { MailService } = await import("../src/mail/mail.service.js");
const { DATABASE_CONNECTION } = await import("../src/database/database-connection.js");
const { user: userTable, verification: verificationTable } = await import("../src/db/auth-schema.js");
const { eq } = await import("drizzle-orm");

let app: INestApplication;
let base: string;

/** One "device" = one browser cookie jar. */
class Device {
  jar = new Map<string, string>();
  async req(path: string, body?: unknown, method?: string) {
    const res = await fetch(base + path, {
      method: method ?? (body === undefined ? "GET" : "POST"),
      headers: {
        origin: "http://localhost:3000", // Better Auth CSRF check expects the configured origin
        cookie: [...this.jar].map(([k, v]) => `${k}=${v}`).join("; "),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(";");
      const [k, v] = [pair.slice(0, pair.indexOf("=")), pair.slice(pair.indexOf("=") + 1)];
      if (v === "" || attrs.some((a) => /max-age=0\b/i.test(a.trim()))) this.jar.delete(k);
      else this.jar.set(k, v);
    }
    return { status: res.status, body: await res.json().catch(() => null) };
  }
  has(name: string) {
    return this.jar.has(`better-auth.${name}`);
  }
}

const email = "alice@example.com";
const password = "correct-horse-battery";

beforeAll(async () => {
  app = await NestFactory.create(AppModule, { bodyParser: false, logger: false });
  configureApp(app);
  await app.listen(0);
  base = `http://localhost:${(app.getHttpServer().address() as { port: number }).port}`;
  const d = new Device();
  expect((await d.req("/api/auth/sign-up/email", { email, password, name: "Alice" })).status).toBe(200);
});
afterAll(() => app?.close());

describe("NestJS guard", () => {
  it("rejects /api/me without a session, accepts it with one", async () => {
    const d = new Device();
    expect((await d.req("/api/me")).status).toBe(401);
    await d.req("/api/auth/sign-in/email", { email, password });
    const me = await d.req("/api/me");
    expect(me.status).toBe(200);
    expect(me.body.user.email).toBe(email);
  });
});

describe("passkey options endpoints", () => {
  it("registration options need a session", async () => {
    expect((await new Device().req("/api/auth/passkey/generate-register-options")).status).toBe(401);
  });

  it("registration options carry rp, user and a challenge, and set the challenge cookie", async () => {
    const d = new Device();
    await d.req("/api/auth/sign-in/email", { email, password });
    const { status, body } = await d.req("/api/auth/passkey/generate-register-options");
    expect(status).toBe(200);
    expect(body.rp).toMatchObject({ id: "localhost", name: "NestJS Better Auth Passkeys Demo" });
    expect(body.user.name).toBe(email);
    expect(body.challenge).toMatch(/^[\w-]{16,}$/);
    expect(body.pubKeyCredParams.length).toBeGreaterThan(0);
    expect(d.has("better-auth-passkey")).toBe(true);
  });

  it("authentication options are anonymous and carry rpId and a fresh challenge", async () => {
    const a = await new Device().req("/api/auth/passkey/generate-authenticate-options");
    const b = await new Device().req("/api/auth/passkey/generate-authenticate-options");
    expect(a.status).toBe(200);
    expect(a.body.rpId).toBe("localhost");
    expect(a.body.challenge).not.toBe(b.body.challenge);
  });

  it("a made-up assertion does not sign anyone in", async () => {
    const d = new Device();
    await d.req("/api/auth/passkey/generate-authenticate-options");
    const r = await d.req("/api/auth/passkey/verify-authentication", {
      response: { id: "bogus", rawId: "bogus", type: "public-key", response: {} },
    });
    expect(r.status).toBeGreaterThanOrEqual(400);
    expect(d.has("session_token")).toBe(false);
  });
});

describe("device binding (two-factor trusted devices)", () => {
  const trusted = new Device();

  async function passOtp(d: Device, trustDevice: boolean) {
    expect((await d.req("/api/auth/two-factor/send-otp", {})).status).toBe(200);
    const code = app.get(MailService).lastMessage?.text.match(/\d{6}/)?.[0];
    return d.req("/api/auth/two-factor/verify-otp", { code, trustDevice });
  }

  beforeAll(async () => {
    await trusted.req("/api/auth/sign-in/email", { email, password });
    expect((await trusted.req("/api/auth/two-factor/enable", { password, method: "otp" })).status).toBe(200);
    await trusted.req("/api/auth/sign-out", {});
  });

  it("first login on a device asks for the second factor; verifying with trustDevice binds it", async () => {
    const r = await trusted.req("/api/auth/sign-in/email", { email, password });
    expect(r.body.twoFactorRedirect).toBe(true);
    expect(trusted.has("session_token")).toBe(false);

    const v = await passOtp(trusted, true);
    expect(v.status).toBe(200);
    expect(trusted.has("session_token")).toBe(true);
    expect(trusted.has("trust_device")).toBe(true);
    await trusted.req("/api/auth/sign-out", {});
  });

  it("the trusted device skips the second factor and gets a rotated trust cookie", async () => {
    const before = trusted.jar.get("better-auth.trust_device");
    const r = await trusted.req("/api/auth/sign-in/email", { email, password });
    expect(r.body.twoFactorRedirect).toBeUndefined();
    expect(trusted.has("session_token")).toBe(true);
    expect(trusted.jar.get("better-auth.trust_device")).not.toBe(before);
    await trusted.req("/api/auth/sign-out", {});
  });

  it("a new device has to verify again", async () => {
    const fresh = new Device();
    const r = await fresh.req("/api/auth/sign-in/email", { email, password });
    expect(r.body.twoFactorRedirect).toBe(true);
    expect(fresh.has("session_token")).toBe(false);
  });

  it("verifying without trustDevice does not bind the device", async () => {
    const d = new Device();
    await d.req("/api/auth/sign-in/email", { email, password });
    await passOtp(d, false);
    expect(d.has("session_token")).toBe(true);
    expect(d.has("trust_device")).toBe(false);
  });

  it("a copied trust cookie is single-use: replaying the old value fails", async () => {
    const stolen = trusted.jar.get("better-auth.trust_device")!;
    await trusted.req("/api/auth/sign-in/email", { email, password }); // rotates it
    const attacker = new Device();
    attacker.jar.set("better-auth.trust_device", stolen);
    const r = await attacker.req("/api/auth/sign-in/email", { email, password });
    expect(r.body.twoFactorRedirect).toBe(true);
  });

  it("a forged trust cookie is rejected", async () => {
    const d = new Device();
    d.jar.set("better-auth.trust_device", "forged.value");
    const r = await d.req("/api/auth/sign-in/email", { email, password });
    expect(r.body.twoFactorRedirect).toBe(true);
  });

  it("delivers the OTP through MailService", async () => {
    const d = new Device();
    await d.req("/api/auth/sign-in/email", { email, password });
    expect((await d.req("/api/auth/two-factor/send-otp", {})).status).toBe(200);
    const message = app.get(MailService).lastMessage;
    expect(message?.to).toBe(email);
    expect(message?.text).toMatch(/\d{6}/);
  });
});

describe("auth secret", () => {
  it("rejects a missing or short BETTER_AUTH_SECRET", () => {
    expect(() => assertAuthSecret(undefined)).toThrow(/32 characters/);
    expect(() => assertAuthSecret("too-short")).toThrow(/32 characters/);
    expect(assertAuthSecret("test-secret-test-secret-test-secret").length).toBeGreaterThanOrEqual(32);
  });
});

describe("notes ownership", () => {
  const ada = new Device();
  const bob = new Device();
  const admin = new Device();
  let adaNoteId: string;

  beforeAll(async () => {
    expect((await ada.req("/api/auth/sign-up/email", { email: "ada@example.com", password, name: "Ada" })).status).toBe(200);
    expect((await bob.req("/api/auth/sign-up/email", { email: "bob@example.com", password, name: "Bob" })).status).toBe(200);
    expect(
      (
        await admin.req("/api/auth/sign-up/email", {
          email: "admin@example.com",
          password,
          name: "Admin",
          role: "admin", // ignored: role is input:false
        })
      ).status,
    ).toBe(200);
    expect((await admin.req("/api/me")).body.user.role).toBe("user");
    // Promote server-side, the only way to become admin.
    app.get(DATABASE_CONNECTION).update(userTable).set({ role: "admin" }).where(eq(userTable.email, "admin@example.com")).run();
    const created = await ada.req("/api/notes", { title: "Ada's note", content: "secret" });
    expect(created.status).toBe(201);
    adaNoteId = created.body.id;
  });

  it("lets a user see and delete only their own notes, and an admin see and delete all", async () => {
    const adaList = await ada.req("/api/notes");
    expect(adaList.status).toBe(200);
    expect(adaList.body.map((n: { id: string }) => n.id)).toEqual([adaNoteId]);

    const bobCreated = await bob.req("/api/notes", { title: "Bob's note", content: "also secret" });
    expect(bobCreated.status).toBe(201);
    expect((await ada.req("/api/notes")).body.map((n: { id: string }) => n.id)).not.toContain(bobCreated.body.id);
    expect((await bob.req("/api/notes")).body.map((n: { id: string }) => n.id)).toEqual([bobCreated.body.id]);

    expect((await bob.req(`/api/notes/${adaNoteId}`, undefined, "DELETE")).body.deleted).toBe(false);
    expect((await ada.req("/api/notes")).body.map((n: { id: string }) => n.id)).toContain(adaNoteId);

    const me = await admin.req("/api/me");
    expect(me.body.user.role).toBe("admin");
    const all = await admin.req("/api/notes");
    expect(all.body.map((n: { id: string }) => n.id)).toEqual(expect.arrayContaining([adaNoteId, bobCreated.body.id]));
    expect((await admin.req(`/api/notes/${adaNoteId}`, undefined, "DELETE")).body.deleted).toBe(true);
    expect((await ada.req("/api/notes")).body.map((n: { id: string }) => n.id)).not.toContain(adaNoteId);
  });

  it("rejects a note body that fails the DTO", async () => {
    expect((await ada.req("/api/notes", {})).status).toBe(400);
    expect((await ada.req("/api/notes", { title: "", content: "x" })).status).toBe(400);
  });
});

describe("device key binding", () => {
  const password = "correct-horse-battery";

  async function p256(extractable = false) {
    return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, extractable, ["sign", "verify"]);
  }

  async function publicJwk(pair: CryptoKeyPair) {
    return crypto.subtle.exportKey("jwk", pair.publicKey);
  }

  async function signNonce(privateKey: CryptoKey, nonce: string) {
    const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, Buffer.from(nonce, "base64url"));
    return Buffer.from(sig).toString("base64url");
  }

  /** Signed-up user with 2FA on, one bound device, and no session. */
  async function boundUser(email: string) {
    const d = new Device();
    const signed = await d.req("/api/auth/sign-up/email", { email, password, name: email });
    expect(signed.status).toBe(200);
    const pair = await p256();
    const registered = await d.req("/api/auth/device-binding/register", { publicKey: await publicJwk(pair), name: "vitest" });
    expect(registered.status).toBe(200);
    expect(typeof registered.body.deviceId).toBe("string");
    expect((await d.req("/api/auth/two-factor/enable", { password, method: "otp" })).status).toBe(200);
    await d.req("/api/auth/sign-out", {});
    return { d, deviceId: registered.body.deviceId as string, privateKey: pair.privateKey, userId: signed.body.user.id as string };
  }

  async function pending(d: Device, email: string) {
    const r = await d.req("/api/auth/sign-in/email", { email, password });
    expect(r.body.twoFactorRedirect).toBe(true);
    expect(d.has("session_token")).toBe(false);
  }

  it("binds a key, then a signature finishes 2FA and no OTP is sent", async () => {
    const { d, deviceId, privateKey } = await boundUser("bind-ok@example.com");
    const before = app.get(MailService).lastMessage;
    await pending(d, "bind-ok@example.com");
    const challenge = await d.req("/api/auth/device-binding/challenge", { deviceId });
    expect(challenge.status).toBe(200);
    const verified = await d.req("/api/auth/device-binding/verify", {
      deviceId,
      signature: await signNonce(privateKey, challenge.body.nonce),
    });
    expect(verified.status).toBe(200);
    expect(d.has("session_token")).toBe(true);
    expect(app.get(MailService).lastMessage).toBe(before);

    const listed = await d.req("/api/auth/device-binding/list");
    expect(listed.status).toBe(200);
    expect(listed.body.devices.map((device: { id: string }) => device.id)).toEqual([deviceId]);
  });

  it("rejects a signature from a different key and creates no session", async () => {
    const { d, deviceId } = await boundUser("bind-bad-sig@example.com");
    await pending(d, "bind-bad-sig@example.com");
    const challenge = await d.req("/api/auth/device-binding/challenge", { deviceId });
    const other = await p256();
    const verified = await d.req("/api/auth/device-binding/verify", {
      deviceId,
      signature: await signNonce(other.privateKey, challenge.body.nonce),
    });
    expect(verified.status).toBeGreaterThanOrEqual(400);
    expect(d.has("session_token")).toBe(false);
  });

  it("rejects a replayed nonce", async () => {
    const { d, deviceId, privateKey } = await boundUser("bind-replay@example.com");
    await pending(d, "bind-replay@example.com");
    const challenge = await d.req("/api/auth/device-binding/challenge", { deviceId });
    const signature = await signNonce(privateKey, challenge.body.nonce);
    expect((await d.req("/api/auth/device-binding/verify", { deviceId, signature })).status).toBe(200);
    await d.req("/api/auth/sign-out", {});
    await pending(d, "bind-replay@example.com");
    const replay = await d.req("/api/auth/device-binding/verify", { deviceId, signature });
    expect(replay.status).toBeGreaterThanOrEqual(400);
    expect(d.has("session_token")).toBe(false);
  });

  it("rejects an expired nonce", async () => {
    const { d, deviceId, privateKey, userId } = await boundUser("bind-expired@example.com");
    await pending(d, "bind-expired@example.com");
    const challenge = await d.req("/api/auth/device-binding/challenge", { deviceId });
    const signature = await signNonce(privateKey, challenge.body.nonce);
    app
      .get(DATABASE_CONNECTION)
      .update(verificationTable)
      .set({ expiresAt: new Date(Date.now() - 60_000) })
      .where(eq(verificationTable.identifier, `device-binding:${userId}:${deviceId}`))
      .run();
    const verified = await d.req("/api/auth/device-binding/verify", { deviceId, signature });
    expect(verified.status).toBeGreaterThanOrEqual(400);
    expect(d.has("session_token")).toBe(false);
  });

  it("rejects a revoked device", async () => {
    const { d, deviceId, privateKey } = await boundUser("bind-revoked@example.com");
    await pending(d, "bind-revoked@example.com");
    const challenge = await d.req("/api/auth/device-binding/challenge", { deviceId });
    expect(
      (await d.req("/api/auth/device-binding/verify", { deviceId, signature: await signNonce(privateKey, challenge.body.nonce) })).status,
    ).toBe(200);
    expect((await d.req("/api/auth/device-binding/revoke", { deviceId })).status).toBe(200);
    expect((await d.req("/api/auth/device-binding/list")).body.devices).toEqual([]);
    await d.req("/api/auth/sign-out", {});
    await pending(d, "bind-revoked@example.com");
    const again = await d.req("/api/auth/device-binding/challenge", { deviceId });
    expect(again.status).toBeGreaterThanOrEqual(400);
    expect(d.has("session_token")).toBe(false);
  });

  it("rejects another user's device id", async () => {
    const alice = await boundUser("bind-alice@example.com");
    const bob = await boundUser("bind-bob@example.com");
    await pending(alice.d, "bind-alice@example.com");
    const challenge = await alice.d.req("/api/auth/device-binding/challenge", { deviceId: bob.deviceId });
    expect(challenge.status).toBeGreaterThanOrEqual(400);
    const verified = await alice.d.req("/api/auth/device-binding/verify", {
      deviceId: bob.deviceId,
      signature: await signNonce(bob.privateKey, "not-a-real-nonce"),
    });
    expect(verified.status).toBeGreaterThanOrEqual(400);
    expect(alice.d.has("session_token")).toBe(false);
  });

  it("rejects challenge and verify when no 2FA sign-in is pending", async () => {
    const d = new Device();
    expect((await d.req("/api/auth/sign-up/email", { email: "bind-open@example.com", password, name: "Open" })).status).toBe(200);
    const pair = await p256();
    const registered = await d.req("/api/auth/device-binding/register", { publicKey: await publicJwk(pair), name: "vitest" });
    const deviceId = registered.body.deviceId as string;
    expect((await d.req("/api/auth/device-binding/challenge", { deviceId })).status).toBeGreaterThanOrEqual(400);
    expect(
      (await d.req("/api/auth/device-binding/verify", { deviceId, signature: "aaaa" })).status,
    ).toBeGreaterThanOrEqual(400);
    const anon = new Device();
    expect((await anon.req("/api/auth/device-binding/challenge", { deviceId })).status).toBeGreaterThanOrEqual(400);
    expect((await anon.req("/api/auth/device-binding/verify", { deviceId, signature: "aaaa" })).status).toBeGreaterThanOrEqual(400);
  });

  it("rejects a private JWK and a non-P-256 key, and requires a session to register, list and revoke", async () => {
    const anon = new Device();
    const pair = await p256(true);
    const pub = await publicJwk(pair);
    expect((await anon.req("/api/auth/device-binding/register", { publicKey: pub, name: "x" })).status).toBe(401);
    expect((await anon.req("/api/auth/device-binding/list")).status).toBe(401);
    expect((await anon.req("/api/auth/device-binding/revoke", { deviceId: "x" })).status).toBe(401);

    const d = new Device();
    expect((await d.req("/api/auth/sign-up/email", { email: "bind-jwk@example.com", password, name: "Jwk" })).status).toBe(200);
    const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
    expect(priv.d).toBeTruthy();
    expect((await d.req("/api/auth/device-binding/register", { publicKey: priv, name: "private" })).status).toBeGreaterThanOrEqual(400);

    const p384 = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-384" }, true, ["sign", "verify"]);
    const p384Jwk = await crypto.subtle.exportKey("jwk", p384.publicKey);
    expect((await d.req("/api/auth/device-binding/register", { publicKey: p384Jwk, name: "p384" })).status).toBeGreaterThanOrEqual(400);

    const rsa = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const rsaJwk = await crypto.subtle.exportKey("jwk", rsa.publicKey);
    expect((await d.req("/api/auth/device-binding/register", { publicKey: rsaJwk, name: "rsa" })).status).toBeGreaterThanOrEqual(400);

    const other = new Device();
    expect((await other.req("/api/auth/sign-up/email", { email: "bind-victim@example.com", password, name: "Victim" })).status).toBe(200);
    const victim = await other.req("/api/auth/device-binding/register", { publicKey: pub, name: "victim" });
    expect(victim.status).toBe(200);
    expect((await d.req("/api/auth/device-binding/revoke", { deviceId: victim.body.deviceId })).status).toBeGreaterThanOrEqual(400);
    const stillThere = await other.req("/api/auth/device-binding/list");
    expect(stillThere.body.devices.map((device: { id: string }) => device.id)).toContain(victim.body.deviceId);
  });
});
