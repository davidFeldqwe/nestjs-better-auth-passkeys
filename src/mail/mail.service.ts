import { Inject, Injectable } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { createTransport, type Transporter } from "nodemailer";

export type SentMail = { to: string; subject: string; text: string };

@Injectable()
export class MailService {
  /** Last message handed to nodemailer. Tests read the OTP from here. */
  lastMessage: SentMail | null = null;
  private readonly transporter: Transporter;

  constructor(@Inject(ConfigService) private readonly config: ConfigService) {
    const host = this.config.get<string>("SMTP_HOST");
    this.transporter = host
      ? createTransport({
          host,
          port: Number(this.config.get<string>("SMTP_PORT") ?? 587),
          auth: {
            user: this.config.get<string>("SMTP_USER"),
            pass: this.config.get<string>("SMTP_PASS"),
          },
        })
      : createTransport({ jsonTransport: true });
  }

  async sendOtp(to: string, otp: string) {
    const message: SentMail = {
      to,
      subject: "Your verification code",
      text: `Your verification code is ${otp}`,
    };
    await this.transporter.sendMail({
      from: this.config.get<string>("SMTP_FROM") ?? "noreply@localhost",
      ...message,
    });
    this.lastMessage = message;
    if (!this.config.get<string>("SMTP_HOST")) console.log(`[2FA] OTP for ${to}: ${otp}`);
  }
}
