import { ValidationPipe, type INestApplication } from "@nestjs/common";

export function configureApp(app: INestApplication) {
  app.useGlobalPipes(new ValidationPipe({ whitelist: true }));
}
