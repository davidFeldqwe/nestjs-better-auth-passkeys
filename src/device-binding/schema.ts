import { index, integer, sqliteTable, text } from "drizzle-orm/sqlite-core";
import { user } from "../db/auth-schema.js";

// Public half of a browser ECDSA P-256 key. The private key never leaves the browser.
export const deviceBinding = sqliteTable(
  "device_binding",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    publicKey: text("public_key").notNull(),
    name: text("name").notNull(),
    createdAt: integer("created_at", { mode: "timestamp_ms" }).notNull(),
    lastUsedAt: integer("last_used_at", { mode: "timestamp_ms" }),
    revokedAt: integer("revoked_at", { mode: "timestamp_ms" }),
  },
  (table) => [index("deviceBinding_userId_idx").on(table.userId)],
);
