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
import {
  createSigner,
  DEFAULT_HOMESERVER_Z32,
  parseAuthRequest,
  performApproval,
  relayHost,
  type ParsedAuthRequest,
  type PubkySession,
} from "@/lib/pubky";

const DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const IDLE_MS = 5 * 60 * 1000;

const SS = {
  idToken: "passport.idToken",
  idExp: "passport.idExp",
  accessToken: "passport.accessToken",
  accessExp: "passport.accessExp",
};

type AuthStatus =
  | { kind: "idle" }
  | { kind: "approving" }
  | { kind: "approved" }
  | { kind: "error"; message: string };

type Status =
  | { kind: "loading" }
  | { kind: "idle" }
  | { kind: "signed-in" }
  | { kind: "working"; message: string }
  | { kind: "unlocked"; pubkyZ32: string; blob: Blob; file: DriveFile; created: boolean }
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

function readAuthUrlFromLocation(): string | null {
  try {
    const url = new URL(window.location.href);
    const param = url.searchParams.get("authUrl");
    if (!param) return null;
    url.searchParams.delete("authUrl");
    const cleaned = url.pathname + (url.searchParams.toString() ? `?${url.searchParams}` : "") + url.hash;
    window.history.replaceState(null, "", cleaned);
    return param;
  } catch {
    return null;
  }
}

export default function Page() {
  const [status, setStatus] = useState<Status>({ kind: "loading" });
  const [pendingAuth, setPendingAuth] = useState<ParsedAuthRequest | null>(null);
  const [pasteValue, setPasteValue] = useState("");
  const [pasteError, setPasteError] = useState<string | null>(null);
  const [parsing, setParsing] = useState(false);
  const [authStatus, setAuthStatus] = useState<AuthStatus>({ kind: "idle" });
  const [showDebug, setShowDebug] = useState(false);

  const secretRef = useRef<Uint8Array | null>(null);
  const signerSessionRef = useRef<PubkySession | null>(null);
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const wrapKeyRef = useRef<CryptoKey | null>(null);
  const wrapKeyPromiseRef = useRef<Promise<CryptoKey> | null>(null);
  const emailRef = useRef<string | null>(null);
  const rehydratedRef = useRef(false);
  const pendingDeepLinkRef = useRef<string | null>(null);
  const homeserverEnsuredRef = useRef(false);

  const signOut = useCallback(() => {
    wipe(secretRef.current);
    secretRef.current = null;
    signerSessionRef.current = null;
    wrapKeyRef.current = null;
    wrapKeyPromiseRef.current = null;
    emailRef.current = null;
    homeserverEnsuredRef.current = false;
    setPendingAuth(null);
    setPasteValue("");
    setPasteError(null);
    setAuthStatus({ kind: "idle" });
    Object.values(SS).forEach((k) => sessionStorage.removeItem(k));
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

    setStatus({ kind: "working", message: "Initializing Pubky…" });
    const session = await createSigner(secret);
    signerSessionRef.current = session;

    setStatus({
      kind: "unlocked",
      pubkyZ32: session.publicKeyZ32,
      blob,
      file,
      created,
    });
  }, []);

  useEffect(() => {
    if (rehydratedRef.current) return;
    rehydratedRef.current = true;
    pendingDeepLinkRef.current = readAuthUrlFromLocation();
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
    if (status.kind !== "unlocked") return;
    const deeplink = pendingDeepLinkRef.current;
    if (!deeplink) return;
    pendingDeepLinkRef.current = null;
    (async () => {
      try {
        const parsed = await parseAuthRequest(deeplink);
        setPendingAuth(parsed);
        setAuthStatus({ kind: "idle" });
      } catch (err) {
        setPasteError((err as Error).message);
      }
    })();
  }, [status.kind]);

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

  const handleParsePaste = async () => {
    setPasteError(null);
    setParsing(true);
    try {
      const parsed = await parseAuthRequest(pasteValue);
      setPendingAuth(parsed);
      setAuthStatus({ kind: "idle" });
      setPasteValue("");
    } catch (err) {
      setPasteError((err as Error).message);
    } finally {
      setParsing(false);
    }
  };

  const handleDeny = () => {
    setPendingAuth(null);
    setAuthStatus({ kind: "idle" });
  };

  const handleApprove = async () => {
    if (!pendingAuth) return;
    const session = signerSessionRef.current;
    if (!session) {
      setAuthStatus({ kind: "error", message: "Signer not ready" });
      return;
    }
    setAuthStatus({ kind: "approving" });
    try {
      await performApproval(session.signer, pendingAuth, {
        defaultHomeserverZ32: DEFAULT_HOMESERVER_Z32,
        alreadyEnsured: homeserverEnsuredRef.current,
      });
      homeserverEnsuredRef.current = true;
      setAuthStatus({ kind: "approved" });
    } catch (err) {
      setAuthStatus({ kind: "error", message: (err as Error).message });
    }
  };

  const handleApprovedDismiss = () => {
    setPendingAuth(null);
    setAuthStatus({ kind: "idle" });
  };

  return (
    <main className="min-h-full flex items-center justify-center p-6">
      <div className="w-full max-w-xl space-y-6">
        <header className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Passport</h1>
          <p className="text-sm text-neutral-400">
            A Pubky signer. Your key lives encrypted in your Google Drive, unlocked only with both Google and this app.
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
          <div className="space-y-4">
            <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wide text-neutral-400">
                  Your Pubky
                </span>
                <button
                  className="text-xs text-neutral-400 hover:text-neutral-200"
                  onClick={signOut}
                >
                  Sign out
                </button>
              </div>
              <div className="flex items-center gap-3">
                <pre className="flex-1 break-all whitespace-pre-wrap rounded bg-black/40 p-3 font-mono text-sm">
                  {status.pubkyZ32}
                </pre>
                <button
                  className="text-xs text-neutral-400 hover:text-neutral-200"
                  onClick={() => navigator.clipboard.writeText(status.pubkyZ32)}
                >
                  Copy
                </button>
              </div>
              {status.created && (
                <p className="text-xs text-green-400">
                  New passport created — this address is now tied to your Google account.
                </p>
              )}
            </div>

            {pendingAuth ? (
              <ApprovalCard
                request={pendingAuth}
                pubkyZ32={status.pubkyZ32}
                authStatus={authStatus}
                onApprove={handleApprove}
                onDeny={handleDeny}
                onDismiss={handleApprovedDismiss}
              />
            ) : (
              <PasteCard
                value={pasteValue}
                error={pasteError}
                parsing={parsing}
                onChange={(v) => {
                  setPasteValue(v);
                  if (pasteError) setPasteError(null);
                }}
                onContinue={handleParsePaste}
              />
            )}

            <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-4">
              <button
                className="text-xs text-neutral-400 hover:text-neutral-200"
                onClick={() => setShowDebug((s) => !s)}
              >
                {showDebug ? "Hide" : "Show"} debug · Drive blob
              </button>
              {showDebug && (
                <div className="mt-3 space-y-2">
                  <p className="text-xs text-neutral-500 break-all">
                    appDataFolder/{status.file.name} · id {status.file.id}
                  </p>
                  <pre className="break-all whitespace-pre-wrap rounded bg-black/40 p-3 font-mono text-xs">
                    {JSON.stringify(status.blob, null, 2)}
                  </pre>
                </div>
              )}
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

function ApprovalCard({
  request,
  pubkyZ32,
  authStatus,
  onApprove,
  onDeny,
  onDismiss,
}: {
  request: ParsedAuthRequest;
  pubkyZ32: string;
  authStatus: AuthStatus;
  onApprove: () => void;
  onDeny: () => void;
  onDismiss: () => void;
}) {
  if (authStatus.kind === "approved") {
    return (
      <div className="rounded-lg border border-green-900 bg-green-950/40 p-6 space-y-3">
        <p className="text-sm font-medium text-green-300">Authorized</p>
        <p className="text-xs text-green-200/80">
          The auth token was sent to the relay. You can close this tab or return to the requesting app.
        </p>
        <button
          className="rounded bg-green-700 px-3 py-1.5 text-sm font-medium text-white hover:bg-green-600"
          onClick={onDismiss}
        >
          OK
        </button>
      </div>
    );
  }

  const busy = authStatus.kind === "approving";
  const isSignup = request.kind === "signup";

  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6 space-y-4">
      <div>
        <p className="text-lg font-semibold">{isSignup ? "Create account" : "Authorize"}</p>
        <p className="text-xs text-neutral-400">
          {isSignup
            ? "An app is requesting to register this Pubky at a homeserver."
            : "An app is requesting permission to act as this Pubky."}
        </p>
      </div>

      <Row label="Relay" value={relayHost(request.relay)} />
      <Row label="Pubky" value={pubkyZ32} mono />
      {request.kind === "signup" && (
        <div>
          <div className="flex items-center gap-2">
            <p className="text-xs uppercase tracking-wide text-neutral-400">Homeserver</p>
            {request.signupToken && (
              <span className="rounded bg-purple-900/60 px-2 py-0.5 text-[10px] uppercase text-purple-200">
                with invite code
              </span>
            )}
          </div>
          <p className="mt-1 break-all font-mono text-sm">{request.homeserverZ32}</p>
        </div>
      )}

      <div className="space-y-2">
        <p className="text-xs uppercase tracking-wide text-neutral-400">Capabilities</p>
        {request.capabilities.length === 0 ? (
          <p className="text-sm text-neutral-500">No capabilities requested.</p>
        ) : (
          <ul className="space-y-1.5">
            {request.capabilities.map((cap, i) => (
              <li
                key={i}
                className="flex items-center justify-between gap-3 rounded bg-black/30 px-3 py-2"
              >
                <span className="break-all font-mono text-xs text-neutral-200">{cap.path}</span>
                <span className="flex gap-1 shrink-0">
                  {cap.read && (
                    <span className="rounded bg-blue-900/60 px-2 py-0.5 text-[10px] uppercase text-blue-200">
                      read
                    </span>
                  )}
                  {cap.write && (
                    <span className="rounded bg-amber-900/60 px-2 py-0.5 text-[10px] uppercase text-amber-200">
                      write
                    </span>
                  )}
                  {!cap.read && !cap.write && (
                    <span className="rounded bg-neutral-800 px-2 py-0.5 text-[10px] uppercase text-neutral-400">
                      {cap.perms || "none"}
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {authStatus.kind === "error" && (
        <p className="rounded bg-red-950/40 px-3 py-2 text-xs text-red-300">
          {authStatus.message}
        </p>
      )}

      <div className="flex gap-2 pt-2">
        <button
          className="flex-1 rounded border border-neutral-700 px-4 py-2 text-sm font-medium text-neutral-200 hover:bg-neutral-800 disabled:opacity-50"
          onClick={onDeny}
          disabled={busy}
        >
          Deny
        </button>
        <button
          className="flex-1 rounded bg-white px-4 py-2 text-sm font-medium text-black hover:bg-neutral-200 disabled:opacity-50"
          onClick={onApprove}
          disabled={busy}
        >
          {busy
            ? isSignup
              ? "Signing up…"
              : "Authorizing…"
            : isSignup
              ? "Sign up & authorize"
              : "Authorize"}
        </button>
      </div>
    </div>
  );
}

function PasteCard({
  value,
  error,
  parsing,
  onChange,
  onContinue,
}: {
  value: string;
  error: string | null;
  parsing: boolean;
  onChange: (v: string) => void;
  onContinue: () => void;
}) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6 space-y-3">
      <div>
        <p className="text-sm font-medium">Ready to sign</p>
        <p className="text-xs text-neutral-400">
          Paste a <code className="rounded bg-black/40 px-1 font-mono">pubkyauth://</code> URL from the requesting app, or open this page with <code className="rounded bg-black/40 px-1 font-mono">?authUrl=…</code>.
        </p>
      </div>
      <textarea
        className="w-full rounded border border-neutral-800 bg-black/40 p-3 font-mono text-xs placeholder:text-neutral-600 focus:border-neutral-600 focus:outline-none"
        rows={3}
        placeholder="pubkyauth:///?caps=…&secret=…&relay=…"
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {error && <p className="text-xs text-red-400">{error}</p>}
      <button
        className="rounded bg-white px-4 py-2 text-sm font-medium text-black hover:bg-neutral-200 disabled:opacity-50"
        onClick={onContinue}
        disabled={!value.trim() || parsing}
      >
        {parsing ? "Parsing…" : "Continue"}
      </button>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-neutral-400">{label}</p>
      <p className={`mt-1 break-all text-sm ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}
