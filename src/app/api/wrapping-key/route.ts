import { NextRequest, NextResponse } from "next/server";
import { hkdfSync } from "node:crypto";
import { verifyIdToken } from "@/lib/verify-id-token";

export const runtime = "nodejs";

export async function POST(req: NextRequest) {
  const auth = req.headers.get("authorization");
  const idToken = auth?.startsWith("Bearer ") ? auth.slice(7) : null;
  if (!idToken) {
    return NextResponse.json({ error: "missing bearer token" }, { status: 401 });
  }

  let sub: string | undefined;
  try {
    const payload = await verifyIdToken(idToken);
    sub = payload?.sub;
  } catch {
    return NextResponse.json({ error: "invalid id token" }, { status: 401 });
  }
  if (!sub) {
    return NextResponse.json({ error: "invalid id token" }, { status: 401 });
  }

  const serverSecret = process.env.SERVER_SECRET;
  if (!serverSecret) {
    return NextResponse.json({ error: "server misconfigured" }, { status: 500 });
  }

  const keyBytes = hkdfSync("sha256", serverSecret, "passport-v1", `wrap:${sub}`, 32);
  const key = Buffer.from(keyBytes).toString("base64");

  return NextResponse.json({ key, version: "v1" });
}
