"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { GoogleLogin, useGoogleLogin, type CredentialResponse } from "@react-oauth/google";
import {
  decryptSecret,
  encryptSecret,
  importWrappingKey,
  wipe,
  type Blob,
} from "@/lib/crypto-client";
import { downloadBlob, findBlobFile, uploadBlob, type DriveFile } from "@/lib/drive";
import { bytesToHex } from "@/lib/base64";

const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const IDLE_MS = 5 * 60 * 1000;

const SS = {
  idToken: "passport.idToken",
  idExp: "passport.idExp",
  accessToken: "passport.accessToken",
  accessExp: "passport.accessExp",
};

type Status =
  | { kind: "loading" }
  | { kind: "idle" }
  | { kind: "signed-in" }
  | { kind: "working"; message: string }
  | { kind: "unlocked"; hex: string; created: boolean; blob: Blob; file: DriveFile }
  | { kind: "error"; message: string };

function decodeIdToken(idToken: string): { exp: number | null; email: string | null } {
  try {
    const [, payloadB64] = idToken.split(".");
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    return {
      exp: typeof payload.exp === "number" ? payload.exp * 1000 : null,
      email: typeof payload.email === "string" ? payload.email : null,
    };
  } catch {
    return { exp: null, email: null };
  }
}

function storeIdToken(idToken: string) {
  const { exp } = decodeIdToken(idToken);
  sessionStorage.setItem(SS.idToken, idToken);
  if (exp) sessionStorage.setItem(SS.idExp, String(exp));
}

function storeAccessToken(accessToken: string, expiresInSec: number) {
  sessionStorage.setItem(SS.accessToken, accessToken);
  sessionStorage.setItem(SS.accessExp, String(Date.now() + expiresInSec * 1000));
}

function readStoredTokens(): { idToken: string; accessToken: string } | null {
  const idToken = sessionStorage.getItem(SS.idToken);
  const idExp = Number(sessionStorage.getItem(SS.idExp));
  const accessToken = sessionStorage.getItem(SS.accessToken);
  const accessExp = Number(sessionStorage.getItem(SS.accessExp));
  if (!idToken || !accessToken || !idExp || !accessExp) return null;
  const now = Date.now();
  if (idExp < now + 5_000 || accessExp < now + 5_000) return null;
  return { idToken, accessToken };
}

export default function Page() {
  const [status, setStatus] = useState<Status>({ kind: "loading" });
  const [reveal, setReveal] = useState(false);
  const secretRef = useRef<Uint8Array | null>(null);
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wrapKeyRef = useRef<CryptoKey | null>(null);
  const wrapKeyPromiseRef = useRef<Promise<CryptoKey> | null>(null);
  const emailRef = useRef<string | null>(null);
  const rehydratedRef = useRef(false);

  const signOut = useCallback(() => {
    wipe(secretRef.current);
    secretRef.current = null;
    wrapKeyRef.current = null;
    wrapKeyPromiseRef.current = null;
    emailRef.current = null;
    Object.values(SS).forEach((k) => sessionStorage.removeItem(k));
    setReveal(false);
    setStatus({ kind: "idle" });
  }, []);

  const resetIdle = useCallback(() => {
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    idleTimerRef.current = setTimeout(signOut, IDLE_MS);
  }, [signOut]);

  const fetchWrappingKey = useCallback(async (idToken: string) => {
    const res = await fetch("/api/wrapping-key", {
      method: "POST",
      headers: { Authorization: `Bearer ${idToken}` },
    });
    if (!res.ok) throw new Error(`wrapping-key failed: ${res.status}`);
    const { key: wrapKeyB64 } = (await res.json()) as { key: string };
    return importWrappingKey(wrapKeyB64);
  }, []);

  const unlockWithDrive = useCallback(async (accessToken: string) => {
    let wrapKey = wrapKeyRef.current;
    if (!wrapKey) {
      if (!wrapKeyPromiseRef.current) throw new Error("wrapping key missing");
      setStatus({ kind: "working", message: "Fetching wrapping key…" });
      wrapKey = await wrapKeyPromiseRef.current;
    }

    setStatus({ kind: "working", message: "Looking up passport in Drive…" });
    const existing = await findBlobFile(accessToken);

    let secret: Uint8Array;
    let blob: Blob;
    let file: DriveFile;
    let created = false;
    if (existing) {
      setStatus({ kind: "working", message: "Unlocking passport…" });
      blob = await downloadBlob(accessToken, existing.id);
      secret = await decryptSecret(wrapKey, blob);
      file = existing;
    } else {
      setStatus({ kind: "working", message: "Creating new passport…" });
      secret = crypto.getRandomValues(new Uint8Array(32));
      blob = await encryptSecret(wrapKey, secret);
      file = await uploadBlob(accessToken, blob);
      created = true;
    }

    secretRef.current = secret;
    setStatus({ kind: "unlocked", hex: bytesToHex(secret), created, blob, file });
  }, []);

  useEffect(() => {
    if (rehydratedRef.current) return;
    rehydratedRef.current = true;
    const stored = readStoredTokens();
    if (!stored) {
      setStatus({ kind: "idle" });
      return;
    }
    (async () => {
      try {
        setStatus({ kind: "working", message: "Restoring session…" });
        emailRef.current = decodeIdToken(stored.idToken).email;
        wrapKeyRef.current = await fetchWrappingKey(stored.idToken);
        await unlockWithDrive(stored.accessToken);
      } catch (err) {
        console.warn("[passport] rehydrate failed:", err);
        Object.values(SS).forEach((k) => sessionStorage.removeItem(k));
        setStatus({ kind: "idle" });
      }
    })();
  }, [fetchWrappingKey, unlockWithDrive]);

  useEffect(() => {
    const onUnload = () => {
      wipe(secretRef.current);
    };
    window.addEventListener("beforeunload", onUnload);
    return () => window.removeEventListener("beforeunload", onUnload);
  }, []);

  useEffect(() => {
    if (status.kind !== "unlocked") return;
    const events: (keyof WindowEventMap)[] = ["mousemove", "keydown", "click"];
    events.forEach((e) => window.addEventListener(e, resetIdle));
    resetIdle();
    return () => {
      events.forEach((e) => window.removeEventListener(e, resetIdle));
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    };
  }, [status.kind, resetIdle]);

  const requestDriveAccess = useGoogleLogin({
    flow: "implicit",
    scope: DRIVE_SCOPE,
    onSuccess: async (tokenResponse) => {
      try {
        storeAccessToken(tokenResponse.access_token, tokenResponse.expires_in);
        await unlockWithDrive(tokenResponse.access_token);
      } catch (err) {
        setStatus({ kind: "error", message: (err as Error).message });
      }
    },
    onError: () => setStatus({ kind: "error", message: "Drive authorization failed" }),
    onNonOAuthError: (err) => {
      if (err.type === "popup_failed_to_open" || err.type === "popup_closed") {
        setStatus({ kind: "signed-in" });
      }
    },
  });

  const onIdToken = useCallback(
    (response: CredentialResponse) => {
      if (!response.credential) {
        setStatus({ kind: "error", message: "No id token returned" });
        return;
      }
      const credential = response.credential;
      storeIdToken(credential);
      const email = decodeIdToken(credential).email;
      emailRef.current = email;

      const wrapKeyPromise = fetchWrappingKey(credential).then((k) => {
        wrapKeyRef.current = k;
        return k;
      });
      wrapKeyPromise.catch((err) =>
        setStatus({ kind: "error", message: (err as Error).message }),
      );
      wrapKeyPromiseRef.current = wrapKeyPromise;

      setStatus({ kind: "working", message: "Opening Drive access…" });
      requestDriveAccess({
        prompt: "",
        ...(email ? { hint: email } : {}),
      });
    },
    [fetchWrappingKey, requestDriveAccess],
  );

  return (
    <main className="min-h-full flex items-center justify-center p-6">
      <div className="w-full max-w-xl space-y-6">
        <header className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Passport</h1>
          <p className="text-sm text-neutral-400">
            A 32-byte secret encrypted in your Google Drive, unlockable only with both Google and this app.
          </p>
        </header>

        {status.kind === "loading" && (
          <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6">
            <p className="text-sm text-neutral-400">Loading…</p>
          </div>
        )}

        {status.kind === "idle" && (
          <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6 space-y-3">
            <p className="text-sm text-neutral-300">
              Step 1 of 2: Sign in with Google to prove your identity.
            </p>
            <GoogleLogin onSuccess={onIdToken} onError={() => setStatus({ kind: "error", message: "Sign-in failed" })} />
          </div>
        )}

        {status.kind === "signed-in" && (
          <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6 space-y-3">
            <p className="text-sm text-neutral-300">
              Step 2 of 2: Allow access to your Google Drive app storage.
            </p>
            <button
              className="rounded bg-white px-4 py-2 text-sm font-medium text-black hover:bg-neutral-200"
              onClick={() =>
                requestDriveAccess({
                  prompt: "",
                  ...(emailRef.current ? { hint: emailRef.current } : {}),
                })
              }
            >
              Authorize Drive access
            </button>
            <p className="text-xs text-neutral-500">
              Stored in a hidden, app-only folder. Not visible in your main Drive UI.
            </p>
          </div>
        )}

        {status.kind === "working" && (
          <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6">
            <p className="text-sm text-neutral-300">{status.message}</p>
          </div>
        )}

        {status.kind === "error" && (
          <div className="rounded-lg border border-red-900 bg-red-950/40 p-6 space-y-3">
            <p className="text-sm text-red-300">{status.message}</p>
            <button
              className="rounded bg-neutral-800 px-3 py-1.5 text-sm hover:bg-neutral-700"
              onClick={signOut}
            >
              Reset
            </button>
          </div>
        )}

        {status.kind === "unlocked" && (
          <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase tracking-wide text-neutral-400">
                {status.created ? "New passport created" : "Passport unlocked"}
              </span>
              <button
                className="text-xs text-neutral-400 hover:text-neutral-200"
                onClick={signOut}
              >
                Sign out
              </button>
            </div>
            <div>
              <div className="mb-2 flex items-center gap-3">
                <span className="text-xs uppercase tracking-wide text-neutral-400">Secret (32 bytes)</span>
                <button
                  className="text-xs text-neutral-400 hover:text-neutral-200"
                  onClick={() => setReveal((r) => !r)}
                >
                  {reveal ? "Hide" : "Show"}
                </button>
                <button
                  className="text-xs text-neutral-400 hover:text-neutral-200"
                  onClick={() => navigator.clipboard.writeText(status.hex)}
                >
                  Copy
                </button>
              </div>
              <pre className="break-all whitespace-pre-wrap rounded bg-black/40 p-3 font-mono text-sm">
                {reveal ? status.hex : "•".repeat(64)}
              </pre>
            </div>
            <div>
              <div className="mb-2 flex items-center gap-3">
                <span className="text-xs uppercase tracking-wide text-neutral-400">Drive blob</span>
                <button
                  className="text-xs text-neutral-400 hover:text-neutral-200"
                  onClick={() =>
                    navigator.clipboard.writeText(JSON.stringify(status.blob, null, 2))
                  }
                >
                  Copy
                </button>
              </div>
              <p className="mb-2 text-xs text-neutral-500 break-all">
                appDataFolder/{status.file.name} · id {status.file.id}
              </p>
              <pre className="break-all whitespace-pre-wrap rounded bg-black/40 p-3 font-mono text-xs">
                {JSON.stringify(status.blob, null, 2)}
              </pre>
            </div>
            <p className="text-xs text-neutral-500">
              Auto-wipes after 5 minutes of inactivity or when you close the tab.
            </p>
          </div>
        )}
      </div>
    </main>
  );
}
