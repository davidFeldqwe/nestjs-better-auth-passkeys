import { Module } from "@nestjs/common";
import { NotesController } from "./note.controller.js";
import { NotesService } from "./note.service.js";

@Module({ controllers: [NotesController], providers: [NotesService] })
export class NoteModule {}
