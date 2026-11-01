import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { getMigrations } from "better-auth/db/migration";
import { join } from "node:path";
import { AppModule } from "./app.module.js";
import { auth } from "./auth.js";

// Zero-setup: create/upgrade the SQLite tables on boot (same as `npx auth migrate`).
await (await getMigrations(auth.options)).runMigrations();

const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false });
app.useStaticAssets(join(import.meta.dirname, "..", "public"));
await app.listen(Number(process.env.PORT ?? 3000));
console.log(`Open http://localhost:${process.env.PORT ?? 3000}`);
