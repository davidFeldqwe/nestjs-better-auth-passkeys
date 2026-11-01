import { Body, Controller, Delete, Get, Inject, Param, Post } from "@nestjs/common";
import { Session, type UserSession } from "@thallesp/nestjs-better-auth";
import { CreateNoteDto } from "./create-note.dto.js";
import { NotesService } from "./note.service.js";

@Controller("api/notes")
export class NotesController {
  constructor(@Inject(NotesService) private readonly notes: NotesService) {}

  @Get()
  list(@Session() session: UserSession) {
    return this.notes.findAll(session.user);
  }

  @Post()
  create(@Session() session: UserSession, @Body() body: CreateNoteDto) {
    return this.notes.create(body.title, body.content, session.user.id);
  }

  @Delete(":id")
  remove(@Session() session: UserSession, @Param("id") id: string) {
    return this.notes.remove(id, session.user);
  }
}
