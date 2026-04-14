import { OAuth2Client, type TokenPayload } from "google-auth-library";

const client = new OAuth2Client();

export async function verifyIdToken(token: string): Promise<TokenPayload | undefined> {
  const audience = process.env.GOOGLE_CLIENT_ID;
  if (!audience) throw new Error("GOOGLE_CLIENT_ID not configured");

  const ticket = await client.verifyIdToken({ idToken: token, audience });
  return ticket.getPayload();
}
