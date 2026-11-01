# nestjs-better-auth-passkeys

A small NestJS + TypeScript demo of **passkeys (FIDO2/WebAuthn)** and **device binding (trusted devices for 2FA)** built with [Better Auth](https://www.better-auth.com). SQLite storage, no setup.

> **Scope:** this is a tutorial-level demo. It is not production code. It uses a hard-coded dev secret, `rpID: "localhost"`, OTP codes printed to the console, and no rate limiting, email verification or account recovery.

## What it does

| Feature | How |
|---|---|
| Email/password sign-up and sign-in | Better Auth core (`emailAndPassword`) |
| Passkey registration and sign-in | `@better-auth/passkey` plugin (WebAuthn via SimpleWebAuthn on the server) |
| Second factor | Better Auth `twoFactor` plugin, OTP method (code printed to the server log) |
| Device binding | Better Auth `twoFactor` **trusted devices** (`trustDevice: true`), described below |
| NestJS integration | `@thallesp/nestjs-better-auth`: Better Auth mounted at `/api/auth/*`, global `AuthGuard`, a protected `GET /api/me` |
| Browser page | `public/index.html`: plain HTML and JS, using the browser's native `PublicKeyCredential.parse*OptionsFromJSON()` and `credential.toJSON()` |

### What "device binding" means here

The binding comes from Better Auth's two-factor trusted-device feature. Nothing was custom-built for it:

1. A user with 2FA enabled signs in with a password. The server returns `twoFactorRedirect: true` and no session.
2. The user verifies the OTP with `trustDevice: true`. The server stores a verification row `trust-device-<random>` → `userId` with a 30-day expiry. It also sets a signed, httpOnly `better-auth.trust_device` cookie that holds `HMAC(secret, userId!trustId)!trustId`.
3. On the next password sign-in from that browser, the server checks the HMAC, the DB row, the user and the expiry. If they pass, it **skips the second factor** and **rotates** the identifier and the cookie, so an old copy of the cookie stops working.
4. A browser without the cookie, or with a forged or replayed cookie, gets the 2FA challenge again.

So a "device" here is **a browser cookie jar**. The binding is not hardware-bound or attested. Anyone who copies the current cookie before it rotates can pass as the device. The 2FA gate covers password sign-in only. A passkey sign-in already counts as possession plus user verification, and Better Auth does not run the 2FA step for it.

## Run

Needs Node 22 or later. The browser page needs a recent Chrome, Safari 18.4+ or Firefox 119+ for the native WebAuthn JSON helpers.

```bash
npm install
npm start          # builds, runs migrations on boot, serves http://localhost:3000
```

Open http://localhost:3000:

1. **Sign up**, then **Register passkey**. Your OS or browser passkey prompt appears.
2. **Sign out**, then **Sign in with passkey**, then **GET /api/me** to see the session.
3. **Enable 2FA (OTP)**, then **Sign out**, then **Sign in**. The response shows `twoFactorRedirect: true`.
4. **Send OTP**, copy the code from the server log, then **Verify OTP** with "Trust this device" ticked.
5. Sign out and sign in again: there is no 2FA prompt. A private window (a new device) is asked again.

## Tests

```bash
npm test
```

The tests run against the real Nest app and Better Auth on in-memory SQLite, over HTTP, with one cookie jar per "device".

**Tested:**
- The Nest `AuthGuard`: `/api/me` returns 401 without a session and 200 with one.
- `GET /passkey/generate-register-options`: needs a session; returns `rp.id = localhost`, the user, a challenge and algorithms; sets the challenge cookie.
- `GET /passkey/generate-authenticate-options`: anonymous; returns `rpId` and a fresh challenge each call.
- `POST /passkey/verify-authentication` with a made-up assertion is rejected and creates no session.
- Trusted device: the first login asks for 2FA. Verifying with `trustDevice` sets the cookie. The trusted device then skips 2FA and the cookie rotates. A new device is challenged. Verifying without `trustDevice` does not bind. A replayed old cookie and a forged cookie are both challenged.

**Not tested:**
- No WebAuthn ceremony is faked in the test suite, so successful `verify-registration` and `verify-authentication` are not unit-tested.
- I checked them once by hand in headless Chrome with a CDP virtual authenticator: sign up → register passkey → sign out → passkey sign-in → `/api/me` 200. That script is not part of this repo.
- It has not been tried with a hardware security key or with Touch ID / Windows Hello.

## Guides followed

| Part | Guide |
|---|---|
| Better Auth setup, SQLite, migrations | https://www.better-auth.com/docs/installation · https://www.better-auth.com/docs/adapters/sqlite |
| NestJS integration (`bodyParser: false`, `AuthModule.forRoot`, `@Session`) | https://www.better-auth.com/docs/integrations/nestjs |
| Passkey plugin (`rpID`, `rpName`, `origin`, endpoints) | https://www.better-auth.com/docs/plugins/passkey |
| Two-factor plugin, OTP, trusted devices | https://www.better-auth.com/docs/plugins/2fa |

Where the demo differs from the guides:
- Migrations run on boot with `getMigrations()` instead of `npx auth migrate`, so nothing has to be set up.
- The HTML page calls the plugin's HTTP endpoints (`generate-register-options` → `navigator.credentials.create` → `verify-registration`, and the same pattern for sign-in) directly. It does not use `authClient.passkey.addPasskey()` / `authClient.signIn.passkey()`, because those need a bundler. The client SDK runs the same calls internally.

## Layout

```
src/auth.ts         Better Auth instance (passkey + twoFactor plugins, SQLite)
src/app.module.ts   AuthModule.forRoot + protected GET /api/me
src/main.ts         bootstrap: migrations, bodyParser: false, static page
public/index.html   browser demo page
test/flows.test.ts  server-side flow tests
```

MIT licensed.
