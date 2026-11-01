// DI follows the Better Auth NestJS example: global DB, auth built in forRootAsync.
import { Controller, Get, Module } from "@nestjs/common";
import { ConfigModule, ConfigService } from "@nestjs/config";
import { AuthModule, Session, type UserSession } from "@thallesp/nestjs-better-auth";
import { createAuth } from "./auth.js";
import { assertAuthSecret } from "./config.js";
import { DATABASE_CONNECTION, DatabaseModule, type Database } from "./database/database.module.js";
import { MailModule } from "./mail/mail.module.js";
import { MailService } from "./mail/mail.service.js";
import { NoteModule } from "./note/note.module.js";

@Controller("api")
class MeController {
  // Protected by the global AuthGuard the module registers.
  @Get("me")
  me(@Session() session: UserSession) {
    return { user: session.user };
  }
}

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    DatabaseModule,
    MailModule,
    NoteModule,
    AuthModule.forRootAsync({
      inject: [DATABASE_CONNECTION, ConfigService, MailService],
      useFactory: (db: Database, config: ConfigService, mail: MailService) => {
        const secret = assertAuthSecret(config.get<string>("BETTER_AUTH_SECRET"));
        const port = Number(config.get<string>("PORT") ?? 3000);
        return { auth: createAuth(db, secret, port, mail) };
      },
    }),
  ],
  controllers: [MeController],
})
export class AppModule {}
