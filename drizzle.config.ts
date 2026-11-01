import { defineConfig } from "drizzle-kit";

export default defineConfig({
  dialect: "sqlite",
  schema: ["./src/db/auth-schema.ts", "./src/note/note.schema.ts", "./src/device-binding/schema.ts"],
  out: "./drizzle",
  dbCredentials: { url: process.env.DB_FILE && process.env.DB_FILE !== ":memory:" ? process.env.DB_FILE : "auth.sqlite" },
});
