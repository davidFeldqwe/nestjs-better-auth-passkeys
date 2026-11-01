import { expect, test, type Page } from "@playwright/test";

async function click(page: Page, name: string, done: string) {
  const out = page.locator("#out");
  await page.getByRole("button", { name, exact: true }).click();
  await expect(out).toContainText(done, { timeout: 20_000 });
  return (await out.textContent()) ?? "";
}

test("sign up, register a passkey, and sign back in", async ({ page }) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });

  await page.goto("/");
  const email = `e2e-passkey-${Date.now()}@example.com`;
  await page.locator("#email").fill(email);

  expect(await click(page, "Sign up", "/api/auth/sign-up/email")).toContain("→ 200");
  expect(await click(page, "Register passkey (must be signed in)", "/api/auth/passkey/verify-registration")).toContain("→ 200");
  expect(await click(page, "Sign out", "/api/auth/sign-out")).toContain("→ 200");
  expect(await click(page, "GET /api/me", "/api/me")).toContain("→ 401");
  expect(await click(page, "Sign in with passkey", "/api/auth/passkey/verify-authentication")).toContain("→ 200");
  const me = await click(page, "GET /api/me", "/api/me");
  expect(me).toContain("→ 200");
  expect(me).toContain(email);
});
