# nestjs-better-auth-passkeys

[![CI](https://github.com/davidFeldqwe/nestjs-better-auth-passkeys/actions/workflows/ci.yml/badge.svg)](https://github.com/davidFeldqwe/nestjs-better-auth-passkeys/actions/workflows/ci.yml)

A small NestJS + TypeScript demo of **passkeys (FIDO2/WebAuthn)** and **device binding for 2FA** built with [Better Auth](https://www.better-auth.com). SQLite storage, no setup.

> **Scope:** this is a tutorial-level demo. It is not production code. It uses `rpID: "localhost"`, prints OTP codes to the console when SMTP is not set, and has no rate limiting, email verification or account recovery. Every account gets `role: "user"`. The field is `input: false`, so a client can't make itself admin at sign-up (the example these patterns came from allowed that). Promote an admin directly in the database.

## What it does

| Feature | How |
|---|---|
| Email/password sign-up and sign-in | Better Auth core (`emailAndPassword`) |
| Passkey registration and sign-in | `@better-auth/passkey` plugin (WebAuthn via SimpleWebAuthn on the server) |
| Second factor | Better Auth `twoFactor` plugin. The OTP is sent by an injectable `MailService` (nodemailer). With no `SMTP_HOST`, nodemailer uses `jsonTransport` and the code is printed to the server log |
| Device binding | Two mechanisms, described below. A trusted-device **cookie** (bearer token) and a browser **P-256 key** (proof of possession) |
| NestJS integration | `@thallesp/nestjs-better-auth`: Better Auth mounted at `/api/auth/*`, global `AuthGuard`, a protected `GET /api/me` |
| Notes | `GET/POST /api/notes` and `DELETE /api/notes/:id`. A user sees and deletes only their own notes. An admin sees and deletes all. The create body is a class-validator DTO |
| Browser page | `public/index.html`: plain HTML and JS, using the browser's native `PublicKeyCredential.parse*OptionsFromJSON()` and `credential.toJSON()` |

### Device binding

A password sign-in for a user with 2FA enabled returns `twoFactorRedirect: true` and no session. Two different things can then satisfy the second factor. The 2FA gate covers password sign-in only. A passkey sign-in already counts as possession plus user verification, and Better Auth does not run the 2FA step for it.

**Trusted-device cookie (weak, a bearer token).** This is Better Auth's `twoFactor` `trustDevice: true` flow, unchanged:

1. The user verifies the OTP with `trustDevice: true`. The server stores a verification row `trust-device-<random>` → `userId` with a 30-day expiry. It also sets a signed, httpOnly `better-auth.trust_device` cookie that holds `HMAC(secret, userId!trustId)!trustId`.
2. On the next password sign-in from that browser, the server checks the HMAC, the DB row, the user and the expiry. If they pass, it **skips the second factor** and **rotates** the identifier and the cookie, so an old copy of the cookie stops working.
3. A browser without the cookie, or with a forged or replayed cookie, gets the 2FA challenge again.

Anyone who copies the current cookie before it rotates can pass as the device. The cookie is not hardware-bound or attested.

**Device key (proof of possession).** A custom Better Auth plugin, `src/device-binding/`, stores only a public key. The browser creates a non-extractable ECDSA P-256 key with `crypto.subtle.generateKey`, keeps the `CryptoKey` in IndexedDB, and `POST /api/auth/device-binding/register` sends the public JWK (no `d`). While a 2FA sign-in is pending (the twoFactor plugin's signed `two_factor` cookie), `POST /api/auth/device-binding/challenge` returns a random nonce that expires in 2 minutes. The browser signs the nonce bytes. `POST /api/auth/device-binding/verify` checks the signature with `crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, ...)`, consumes the nonce, and finishes the sign-in the same way OTP verification does: create the session, set the session cookie, delete the pending `two_factor` row and expire that cookie. A bad signature, a replay, an expired nonce, a revoked key, or another user's device does not create a session. The OTP path and the trusted-device cookie still work.

What the key is **not**:

- Browser WebCrypto keys are not hardware-backed or attested. Nothing proves the key sits in a secure element.
- JavaScript cannot export the private key bytes (`extractable: false`), but XSS on this origin can still call `crypto.subtle.sign` with the key while the page is open.
- Clearing site data deletes IndexedDB, and the binding on that browser is gone. The server keeps the public key until it is revoked.

## Run

Needs Node 22 or later. The browser page needs a recent Chrome, Safari 18.4+ or Firefox 119+ for the native WebAuthn JSON helpers.

```bash
cp .env.example .env   # set BETTER_AUTH_SECRET to at least 32 characters
npm install
npm start              # builds, applies drizzle migrations on boot, serves http://localhost:3000
```

`BETTER_AUTH_SECRET`, `PORT`, `DB_FILE` and the `SMTP_*` settings are read with `@nestjs/config`. The process exits at boot if the secret is missing or shorter than 32 characters. Leave `SMTP_HOST` empty for local use. To use Postgres or MySQL instead of SQLite, change the Drizzle driver, `drizzleAdapter`'s `provider`, and the `dialect` in `drizzle.config.ts`, then regenerate the schema (`npx auth generate`) and the migrations (`npx drizzle-kit generate`).

Open http://localhost:3000:

1. **Sign up**, then **Register passkey**. Your OS or browser passkey prompt appears.
2. **Sign out**, then **Sign in with passkey**, then **GET /api/me** to see the session.
3. **Enable 2FA (OTP)**, then **Sign out**, then **Sign in**. The response shows `twoFactorRedirect: true`.
4. **Send OTP**, copy the code from the server log, then **Verify OTP** with "Trust this device" ticked.
5. Sign out and sign in again: there is no 2FA prompt. A private window (a new device) is asked again.
6. Or, while signed in, **Bind this device**. Sign out, sign in with the password, then **Complete 2FA with bound device**. No OTP is sent. **List devices** and **Revoke** manage the public keys.

## Tests

```bash
npm test      # vitest, no browser
npm run e2e   # Playwright, Chromium only
```

`npm test` runs against the real Nest app and Better Auth on in-memory SQLite, over HTTP, with one cookie jar per "device". Vitest does not collect `e2e/`. Playwright does not collect `test/`.

**Tested:**
- The Nest `AuthGuard`: `/api/me` returns 401 without a session and 200 with one.
- `GET /passkey/generate-register-options`: needs a session; returns `rp.id = localhost`, the user, a challenge and algorithms; sets the challenge cookie.
- `GET /passkey/generate-authenticate-options`: anonymous; returns `rpId` and a fresh challenge each call.
- `POST /passkey/verify-authentication` with a made-up assertion is rejected and creates no session.
- Trusted device: the first login asks for 2FA. Verifying with `trustDevice` sets the cookie. The trusted device then skips 2FA and the cookie rotates. A new device is challenged. Verifying without `trustDevice` does not bind. A replayed old cookie and a forged cookie are both challenged.
- The OTP from `send-otp` is the code stored on `MailService`.
- Device key: register stores an EC P-256 public JWK and rejects a JWK that contains `d` or is not P-256. `register`, `list` and `revoke` need a session, and one user cannot revoke another's device. After a password sign-in, a signature from the bound key finishes 2FA and no OTP is sent. A signature from a different key, a replayed nonce, an expired nonce, a revoked device, another user's device, or a challenge with no pending 2FA sign-in is rejected and creates no session.
- `assertAuthSecret` throws when `BETTER_AUTH_SECRET` is missing or shorter than 32 characters. The auth factory calls it, so boot fails the same way.
- Notes: user A cannot see or delete user B's note. An admin can. A body that fails the DTO returns 400.

`npm run e2e` boots the app on a free port (origin and `rpID` follow that port) with a temp SQLite file and runs Chromium:

- Passkey: sign up → register passkey → sign out → `/api/me` 401 → sign in with a CDP virtual authenticator → `/api/me` 200.
- Device key: sign up → enable OTP 2FA → bind this browser → sign out → password sign-in → complete with the bound device → `/api/me` 200, and the page does not call `send-otp` for that sign-in.

**Not tested:**
- The vitest file does not fake a WebAuthn ceremony. The successful passkey ceremony is the Playwright spec above, using Chromium's virtual authenticator, not a hardware key.
- It has not been tried with a hardware security key or with Touch ID / Windows Hello.

## Guides followed

| Part | Guide |
|---|---|
| Better Auth setup, SQLite, migrations | https://www.better-auth.com/docs/installation · https://www.better-auth.com/docs/adapters/sqlite |
| NestJS integration (`bodyParser: false`, `AuthModule.forRootAsync`, `@Session`) | https://www.better-auth.com/docs/integrations/nestjs |
| Passkey plugin (`rpID`, `rpName`, `origin`, endpoints) | https://www.better-auth.com/docs/plugins/passkey |
| Two-factor plugin, OTP, trusted devices | https://www.better-auth.com/docs/plugins/2fa |
| Custom plugin (`createAuthEndpoint`, plugin schema) | https://www.better-auth.com/docs/guides/your-first-plugin |
| Browser ECDSA P-256 key (`SubtleCrypto.generateKey`) | https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey |
| Virtual authenticator (Chrome DevTools WebAuthn, CDP `WebAuthn` domain) | https://developer.chrome.com/docs/devtools/webauthn · https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/ |
| Drizzle adapter (`drizzleAdapter`, schema generate) | https://www.better-auth.com/docs/adapters/drizzle |
| Additional user fields (`role`) | https://www.better-auth.com/docs/concepts/database#extending-core-schema |
| NestJS configuration (`ConfigModule`, `ConfigService`) | https://docs.nestjs.com/techniques/configuration |
| Drizzle with SQLite (`better-sqlite3`, migrations) | https://orm.drizzle.team/docs/sqlite/get-started-sqlite |

The Nest layout — async `AuthModule`, a global database module, `ConfigModule`, and note ownership — was ported from a Better Auth NestJS example. This demo stays on SQLite. It does not add that example's manual auth controller, because the library already mounts the handler. The example typed the note body inline, so validation never ran; this demo uses a class DTO with the global `ValidationPipe`.

Where the demo differs from the guides:
- Migrations are drizzle-kit SQL files, applied on boot with `migrate()`, so nothing has to be set up by hand.
- The OTP goes through `MailService`. With no SMTP host, nodemailer uses `jsonTransport` and the code is logged.
- The HTML page calls the plugin's HTTP endpoints (`generate-register-options` → `navigator.credentials.create` → `verify-registration`, and the same pattern for sign-in) directly. It does not use `authClient.passkey.addPasskey()` / `authClient.signIn.passkey()`, because those need a bundler. The client SDK runs the same calls internally.

## Layout

```
src/auth.ts          createAuth(): passkey + twoFactor + deviceBinding, drizzleAdapter, role field
src/device-binding/  ECDSA device-key plugin and its Drizzle table
src/app.module.ts    ConfigModule, AuthModule.forRootAsync, protected GET /api/me
src/main.ts          bootstrap: bodyParser false, ValidationPipe, static page
src/config.ts        rejects a missing or short BETTER_AUTH_SECRET
src/database/        global Drizzle connection; migrations run when it is created
src/db/              Better Auth tables generated by the CLI (passkey, twoFactor, role)
src/mail/            MailService (nodemailer)
src/note/            note table, ownership, CreateNoteDto
drizzle/             drizzle-kit SQL migrations
drizzle.config.ts
.env.example         BETTER_AUTH_SECRET, PORT, DB_FILE, SMTP_*
public/index.html    browser demo page
test/flows.test.ts   server-side flow tests (vitest)
e2e/                 Playwright specs (passkey ceremony, device key)
playwright.config.ts Chromium only; webServer sets PORT, DB_FILE, BETTER_AUTH_SECRET
```

MIT licensed.
