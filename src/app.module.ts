// Follows https://www.better-auth.com/docs/integrations/nestjs
import { Controller, Get, Module } from "@nestjs/common";
import { AuthModule, Session, type UserSession } from "@thallesp/nestjs-better-auth";
import { auth } from "./auth.js";

@Controller("api")
class MeController {
  // Protected by the global AuthGuard the module registers.
  @Get("me")
  me(@Session() session: UserSession) {
    return { user: session.user };
  }
}

@Module({ imports: [AuthModule.forRoot({ auth })], controllers: [MeController] })
export class AppModule {}
