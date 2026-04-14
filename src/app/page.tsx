"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { GoogleLogin, useGoogleLogin, type CredentialResponse } from "@react-oauth/google";
import {
  decryptSecret,
  encryptSecret,
  importWrappingKey,
  wipe,
} from "@/lib/crypto-client";
import { downloadBlob, findBlobFile, uploadBlob } from "@/lib/drive";
import { bytesToHex } from "@/lib/base64";

const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const IDLE_MS = 5 * 60 * 1000;

type Status =
  | { kind: "idle" }
  | { kind: "signed-in" }
  | { kind: "working"; message: string }
  | { kind: "unlocked"; hex: string; created: boolean }
  | { kind: "error"; message: string };

export default function Page() {
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [reveal, setReveal] = useState(false);
  const secretRef = useRef<Uint8Array | null>(null);
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wrapKeyRef = useRef<CryptoKey | null>(null);

  const signOut = useCallback(() => {
    wipe(secretRef.current);
    secretRef.current = null;
    wrapKeyRef.current = null;
    sessionStorage.clear();
    setReveal(false);
    setStatus({ kind: "idle" });
  }, []);

  const resetIdle = useCallback(() => {
    if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    idleTimerRef.current = setTimeout(signOut, IDLE_MS);
  }, [signOut]);

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

  const unlockWithDrive = useCallback(async (accessToken: string) => {
    const wrapKey = wrapKeyRef.current;
    if (!wrapKey) throw new Error("wrapping key missing");

    setStatus({ kind: "working", message: "Looking up passport in Drive…" });
    const existing = await findBlobFile(accessToken);

    let secret: Uint8Array;
    let created = false;
    if (existing) {
      setStatus({ kind: "working", message: "Unlocking passport…" });
      const blob = await downloadBlob(accessToken, existing.id);
      secret = await decryptSecret(wrapKey, blob);
    } else {
      setStatus({ kind: "working", message: "Creating new passport…" });
      secret = crypto.getRandomValues(new Uint8Array(32));
      const blob = await encryptSecret(wrapKey, secret);
      await uploadBlob(accessToken, blob);
      created = true;
    }

    secretRef.current = secret;
    sessionStorage.setItem("passport.accessToken", accessToken);
    setStatus({ kind: "unlocked", hex: bytesToHex(secret), created });
  }, []);

  const requestDriveAccess = useGoogleLogin({
    flow: "implicit",
    scope: DRIVE_SCOPE,
    onSuccess: async (tokenResponse) => {
      try {
        await unlockWithDrive(tokenResponse.access_token);
      } catch (err) {
        setStatus({ kind: "error", message: (err as Error).message });
      }
    },
    onError: () => setStatus({ kind: "error", message: "Drive authorization failed" }),
  });

  const onIdToken = useCallback(
    async (response: CredentialResponse) => {
      if (!response.credential) {
        setStatus({ kind: "error", message: "No id token returned" });
        return;
      }
      try {
        setStatus({ kind: "working", message: "Fetching wrapping key…" });
        const res = await fetch("/api/wrapping-key", {
          method: "POST",
          headers: { Authorization: `Bearer ${response.credential}` },
        });
        if (!res.ok) throw new Error(`wrapping-key failed: ${res.status}`);
        const { key: wrapKeyB64 } = (await res.json()) as { key: string };
        wrapKeyRef.current = await importWrappingKey(wrapKeyB64);
        setStatus({ kind: "signed-in" });
      } catch (err) {
        setStatus({ kind: "error", message: (err as Error).message });
      }
    },
    [],
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
              onClick={() => requestDriveAccess()}
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
            <p className="text-xs text-neutral-500">
              Auto-wipes after 5 minutes of inactivity or when you close the tab.
            </p>
          </div>
        )}
      </div>
    </main>
  );
}
