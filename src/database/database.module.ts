import { Global, Module } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import Database from "better-sqlite3";
import { drizzle, type BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import { join } from "node:path";
import { schema } from "../db/schema.js";
import { DATABASE_CONNECTION } from "./database-connection.js";

export { DATABASE_CONNECTION };

export type Database = BetterSQLite3Database<typeof schema>;

@Global()
@Module({
  providers: [
    {
      provide: DATABASE_CONNECTION,
      inject: [ConfigService],
      useFactory: (config: ConfigService): Database => {
        const sqlite = new Database(config.get<string>("DB_FILE") ?? "auth.sqlite");
        sqlite.pragma("foreign_keys = ON");
        const db = drizzle(sqlite, { schema });
        // Same connection the app and the tests use, so `npm start` needs no migrate step.
        migrate(db, { migrationsFolder: join(process.cwd(), "drizzle") });
        return db;
      },
    },
  ],
  exports: [DATABASE_CONNECTION],
})
export class DatabaseModule {}
