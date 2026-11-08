import http from "http";
import https from "https";
import { URL } from "url";

export type VaultEvent =
  | "authorization.created"
  | "settlement.completed"
  | "hold.released";

export interface WebhookPayload {
  event: VaultEvent;
  at: string;
  data: Record<string, unknown>;
}

export function emitWebhook(
  url: string | null,
  event: VaultEvent,
  data: Record<string, unknown>
): void {
  if (!url) return;
  const payload: WebhookPayload = {
    event,
    at: new Date().toISOString(),
    data,
  };
  const body = Buffer.from(JSON.stringify(payload));
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return;
  }
  const lib = target.protocol === "https:" ? https : http;
  const req = lib.request(
    target,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "content-length": body.length,
      },
    },
    (res) => {
      res.resume();
    }
  );
  req.on("error", () => undefined);
  req.write(body);
  req.end();
}
