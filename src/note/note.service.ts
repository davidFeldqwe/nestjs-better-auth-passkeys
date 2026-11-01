import { Inject, Injectable } from "@nestjs/common";
import type { UserSession } from "@thallesp/nestjs-better-auth";
import { and, eq } from "drizzle-orm";
import type { Database } from "../database/database.module.js";
import { DATABASE_CONNECTION } from "../database/database-connection.js";
import { note } from "./note.schema.js";

@Injectable()
export class NotesService {
  constructor(@Inject(DATABASE_CONNECTION) private readonly db: Database) {}

  findAll(user: UserSession["user"]) {
    if (user.role === "admin") return this.db.select().from(note).all();
    return this.db.select().from(note).where(eq(note.userId, user.id)).all();
  }

  create(title: string, content: string, userId: string) {
    return this.db.insert(note).values({ title, content, userId }).returning().get();
  }

  remove(noteId: string, user: UserSession["user"]) {
    const where =
      user.role === "admin" ? eq(note.id, noteId) : and(eq(note.id, noteId), eq(note.userId, user.id));
    const result = this.db.delete(note).where(where).run();
    return { deleted: result.changes > 0 };
  }
}
