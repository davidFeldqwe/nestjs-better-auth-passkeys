import { expect, test, type Page } from "@playwright/test";

async function click(page: Page, name: string, done: string) {
  const out = page.locator("#out");
  await page.getByRole("button", { name, exact: true }).click();
  await expect(out).toContainText(done, { timeout: 20_000 });
  return (await out.textContent()) ?? "";
}

test("password sign-in completes with the bound device and sends no OTP", async ({ page }) => {
  const otpCalls: string[] = [];
  page.on("request", (req) => {
    if (req.url().includes("/two-factor/send-otp")) otpCalls.push(req.url());
  });

  await page.goto("/");
  const email = `e2e-device-${Date.now()}@example.com`;
  await page.locator("#email").fill(email);

  // Enabling OTP 2FA does not send a code. The second sign-in uses the device key.
  expect(await click(page, "Sign up", "/api/auth/sign-up/email")).toContain("→ 200");
  expect(await click(page, "Enable 2FA (OTP)", "/api/auth/two-factor/enable")).toContain("→ 200");
  expect(await click(page, "Bind this device", "/api/auth/device-binding/register")).toContain("→ 200");
  expect(await click(page, "Sign out", "/api/auth/sign-out")).toContain("→ 200");

  const signIn = await click(page, "Sign in", "/api/auth/sign-in/email");
  expect(signIn).toContain("twoFactorRedirect");
  expect(await click(page, "GET /api/me", "/api/me")).toContain("→ 401");

  expect(await click(page, "Complete 2FA with bound device", "/api/auth/device-binding/verify")).toContain("→ 200");
  expect(otpCalls).toEqual([]);
  const me = await click(page, "GET /api/me", "/api/me");
  expect(me).toContain("→ 200");
  expect(me).toContain(email);
});
