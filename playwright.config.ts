import { defineConfig } from "@playwright/test";
import os from "node:os";
import path from "node:path";

// rpID and Better Auth's origin are derived from PORT, so the browser and the server share it.
// ponytail: fixed port; set E2E_PORT if 3100 is taken.
const port = Number(process.env.E2E_PORT ?? 3100);

export default defineConfig({
  testDir: "e2e",
  testMatch: /.*\.spec\.ts/,
  workers: 1,
  use: { baseURL: `http://localhost:${port}` },
  // ponytail: @playwright/test 1.61.1 (Chromium r1228). 1.64 does not ship Chromium for macOS 13.
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: {
    command: "npm start",
    url: `http://localhost:${port}`,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      PORT: String(port),
      DB_FILE: path.join(os.tmpdir(), `nestjs-better-auth-e2e-${Date.now()}.sqlite`),
      BETTER_AUTH_SECRET: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
  },
});
