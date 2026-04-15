import { NextRequest, NextResponse } from "next/server";
import { verifyIdToken } from "@/lib/verify-id-token";
import { deriveWrappingKey } from "@/lib/wrapping-key";

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

  try {
    const { key, version } = await deriveWrappingKey(sub);
    return NextResponse.json({ key: key.toString("base64"), version });
  } catch (err) {
    console.error("[wrapping-key] derive failed:", err);
    return NextResponse.json({ error: "server misconfigured" }, { status: 500 });
  }
}
