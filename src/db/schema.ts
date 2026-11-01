import { account, passkey, session, twoFactor, user, verification } from "./auth-schema.js";
import { note } from "../note/note.schema.js";

// Tables the Drizzle client and the Better Auth adapter share.
export const schema = { user, session, account, verification, passkey, twoFactor, note };
