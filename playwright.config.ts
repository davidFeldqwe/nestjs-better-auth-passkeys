import { defineConfig } from "@playwright/test";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

// rpID and Better Auth's origin are derived from PORT, so the browser and the server share this port.
// Playwright loads this file more than once (runner, then worker). A fresh listen(0) each time
// would point the tests at a different port than the webServer. The first load claims the port.
const portFile = path.join(os.tmpdir(), "nestjs-better-auth-e2e.port");

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close();
        reject(new Error("Could not allocate a port"));
        return;
      }
      const port = address.port;
      server.close(() => resolve(port));
    });
  });
}

function claimedPort(): number | undefined {
  try {
    const [port, at] = fs.readFileSync(portFile, "utf8").trim().split("\n");
    const age = Date.now() - Number(at);
    if (age >= 0 && age < 120_000 && Number(port) > 0) return Number(port);
    fs.unlinkSync(portFile);
  } catch {
    // no claim yet
  }
  return undefined;
}

async function resolvePort(): Promise<number> {
  for (let attempt = 0; attempt < 20; attempt++) {
    const existing = claimedPort();
    if (existing) return existing;
    const port = await freePort();
    try {
      fs.writeFileSync(portFile, `${port}\n${Date.now()}\n`, { flag: "wx" });
      return port;
    } catch {
      // another load claimed a port first
    }
  }
  throw new Error("Could not agree on an e2e port");
}

const port = await resolvePort();
const dbFile = path.join(os.tmpdir(), `nestjs-better-auth-e2e-${port}.sqlite`);

export default defineConfig({
  testDir: "e2e",
  testMatch: /.*\.spec\.ts/,
  fullyParallel: false,
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
      DB_FILE: dbFile,
      BETTER_AUTH_SECRET: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
  },
});
