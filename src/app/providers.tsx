"use client";

import { GoogleOAuthProvider } from "@react-oauth/google";

const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID ?? "";

if (typeof window !== "undefined") {
  console.log("[passport] GoogleOAuthProvider clientId:", JSON.stringify(clientId));
  console.log("[passport] window.location.origin:", window.location.origin);
}

export function Providers({ children }: { children: React.ReactNode }) {
  return <GoogleOAuthProvider clientId={clientId}>{children}</GoogleOAuthProvider>;
}
