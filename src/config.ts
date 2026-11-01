// Boot fails here, before Better Auth starts, when the secret is missing or short.
export function assertAuthSecret(secret: string | undefined): string {
  if (typeof secret !== "string" || secret.length < 32) {
    throw new Error(
      "BETTER_AUTH_SECRET must be set and at least 32 characters long. Copy .env.example to .env and set one.",
    );
  }
  return secret;
}
