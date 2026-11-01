import "reflect-metadata";
import { ConfigService } from "@nestjs/config";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { join } from "node:path";
import { AppModule } from "./app.module.js";
import { configureApp } from "./configure-app.js";

const app = await NestFactory.create<NestExpressApplication>(AppModule, { bodyParser: false });
configureApp(app);
app.useStaticAssets(join(import.meta.dirname, "..", "public"));
const port = Number(app.get(ConfigService).get("PORT") ?? 3000);
await app.listen(port);
console.log(`Open http://localhost:${port}`);
