"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  decryptSecret,
  encryptSecret,
  importWrappingKey,
  wipe,
  type Blob,
} from "@/lib/crypto-client";
import { deleteBlob, downloadBlob, findBlobFile, uploadBlob, type DriveFile } from "@/lib/drive";
import {
  createSigner,
  fetchProfile,
  parseAuthRequest,
  performApproval,
  relayHost,
  type ParsedAuthRequest,
  type PubkyProfile,
  type PubkySession,
} from "@/lib/pubky";

const OIDC_SCOPES = "openid email profile https://www.googleapis.com/auth/drive.appdata";
const OIDC_AUTHORIZE_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const IDLE_MS = 5 * 60 * 1000;

const SS = {
  idToken: "passport.idToken",
  idExp: "passport.idExp",
  accessToken: "passport.accessToken",
  accessExp: "passport.accessExp",
  oidcNonce: "passport.oidcNonce",
  oidcState: "passport.oidcState",
};

function randomBase64Url(bytes: number): string {
  const buf = crypto.getRandomValues(new Uint8Array(bytes));
  let bin = "";
  for (const b of buf) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlEncode(text: string): string {
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlDecode(text: string): string {
  const pad = text.length % 4 === 0 ? "" : "=".repeat(4 - (text.length % 4));
  return atob(text.replace(/-/g, "+").replace(/_/g, "/") + pad);
}

function beginGoogleLogin(deepLinkAuthUrl: string | null) {
  const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
  if (!clientId) {
    throw new Error("NEXT_PUBLIC_GOOGLE_CLIENT_ID not configured");
  }
  const nonce = randomBase64Url(32);
  const csrf = randomBase64Url(32);
  const statePayload = deepLinkAuthUrl ? { csrf, authUrl: deepLinkAuthUrl } : { csrf };
  const state = base64UrlEncode(JSON.stringify(statePayload));

  sessionStorage.setItem(SS.oidcNonce, nonce);
  sessionStorage.setItem(SS.oidcState, csrf);

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "id_token token",
    scope: OIDC_SCOPES,
    redirect_uri: window.location.origin,
    nonce,
    state,
    prompt: "consent",
    include_granted_scopes: "true",
  });
  window.location.assign(`${OIDC_AUTHORIZE_ENDPOINT}?${params.toString()}`);
}

type AuthStatus =
  | { kind: "idle" }
  | { kind: "approving" }
  | { kind: "approved" }
  | { kind: "error"; message: string };

type Status =
  | { kind: "loading" }
  | { kind: "idle" }
  | { kind: "working"; message: string }
  | {
      kind: "unlocked";
      pubkyZ32: string;
      blob: Blob;
      file: DriveFile;
      created: boolean;
      profile: PubkyProfile | null | undefined;
    }
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

const DRIVE_APPDATA_SCOPE = "https://www.googleapis.com/auth/drive.appdata";

type OidcFragmentResult =
  | { idToken: string; accessToken: string; expiresIn: number; authUrl: string | null }
  | { error: string };

function consumeOidcFragment(): OidcFragmentResult | null {
  if (typeof window === "undefined") return null;
  const hash = window.location.hash;
  if (!hash || hash.length < 2) return null;
  const params = new URLSearchParams(hash.slice(1));

  const scrub = () => {
    const url = new URL(window.location.href);
    window.history.replaceState(null, "", url.pathname + url.search);
  };

  if (params.has("error")) {
    const msg = params.get("error_description") || params.get("error") || "Sign-in failed";
    scrub();
    return { error: msg };
  }

  const idToken = params.get("id_token");
  const accessToken = params.get("access_token");
  const expiresInRaw = params.get("expires_in");
  const returnedState = params.get("state");
  const returnedScope = params.get("scope") ?? "";
  if (!idToken || !accessToken) return null;

  scrub();

  if (!returnedScope.split(" ").includes(DRIVE_APPDATA_SCOPE)) {
    sessionStorage.removeItem(SS.oidcState);
    sessionStorage.removeItem(SS.oidcNonce);
    return {
      error:
        "Google Drive permission was not granted. On the consent screen, make sure the box for \"See, edit, create and delete only the specific Google Drive files you use with this app\" is checked, then try again.",
    };
  }

  const expectedCsrf = sessionStorage.getItem(SS.oidcState);
  const expectedNonce = sessionStorage.getItem(SS.oidcNonce);
  sessionStorage.removeItem(SS.oidcState);
  sessionStorage.removeItem(SS.oidcNonce);

  if (!expectedCsrf || !expectedNonce || !returnedState) {
    return { error: "OIDC state missing" };
  }

  let statePayload: { csrf?: string; authUrl?: string };
  try {
    statePayload = JSON.parse(base64UrlDecode(returnedState));
  } catch {
    return { error: "OIDC state malformed" };
  }
  if (statePayload.csrf !== expectedCsrf) {
    return { error: "OIDC state mismatch" };
  }

  const payload = decodeIdTokenPayload(idToken);
  if (!payload || payload.nonce !== expectedNonce) {
    return { error: "OIDC nonce mismatch" };
  }

  const expiresIn = Number(expiresInRaw);
  return {
    idToken,
    accessToken,
    expiresIn: Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : 3600,
    authUrl: typeof statePayload.authUrl === "string" ? statePayload.authUrl : null,
  };
}

function decodeIdTokenPayload(idToken: string): Record<string, unknown> | null {
  try {
    const [, b64] = idToken.split(".");
    return JSON.parse(atob(b64.replace(/-/g, "+").replace(/_/g, "/")));
  } catch {
    return null;
  }
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
  const [showBackup, setShowBackup] = useState(false);
  const [backupPass, setBackupPass] = useState("");
  const [backupPass2, setBackupPass2] = useState("");
  const [backupError, setBackupError] = useState<string | null>(null);
  const [showWipe, setShowWipe] = useState(false);
  const [wipeConfirm, setWipeConfirm] = useState("");
  const [wipeError, setWipeError] = useState<string | null>(null);
  const [wiping, setWiping] = useState(false);

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
    setBackupPass("");
    setBackupPass2("");
    setBackupError(null);
    setShowBackup(false);
    Object.values(SS).forEach((k) => sessionStorage.removeItem(k));
    setStatus({ kind: "idle" });
  }, []);

  const wipeEverything = useCallback(async () => {
    setWipeError(null);
    setWiping(true);
    const accessToken = sessionStorage.getItem(SS.accessToken);
    try {
      if (accessToken) {
        try {
          const existing = await findBlobFile(accessToken);
          if (existing) await deleteBlob(accessToken, existing.id);
        } catch (err) {
          console.warn("[passport] wipe: drive delete failed", err);
        }
        try {
          await fetch(
            `https://oauth2.googleapis.com/revoke?token=${encodeURIComponent(accessToken)}`,
            { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" } },
          );
        } catch (err) {
          console.warn("[passport] wipe: token revoke failed", err);
        }
      }
      signOut();
      setShowWipe(false);
      setWipeConfirm("");
    } catch (err) {
      setWipeError((err as Error).message);
    } finally {
      setWiping(false);
    }
  }, [signOut]);

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
      profile: undefined,
    });
  }, []);

  useEffect(() => {
    if (rehydratedRef.current) return;
    rehydratedRef.current = true;
    pendingDeepLinkRef.current = readAuthUrlFromLocation();

    const fragment = consumeOidcFragment();
    if (fragment) {
      if ("error" in fragment) {
        setStatus({ kind: "error", message: fragment.error });
        return;
      }
      if (fragment.authUrl) pendingDeepLinkRef.current = fragment.authUrl;
      storeIdToken(fragment.idToken);
      storeAccessToken(fragment.accessToken, fragment.expiresIn);
      emailRef.current = decodeIdToken(fragment.idToken).email;
      (async () => {
        try {
          setStatus({ kind: "working", message: "Fetching wrapping key…" });
          const wrapKey = await fetchWrappingKey(fragment.idToken);
          wrapKeyRef.current = wrapKey;
          await unlockWithDrive(fragment.accessToken);
        } catch (err) {
          Object.values(SS).forEach((k) => sessionStorage.removeItem(k));
          setStatus({ kind: "error", message: (err as Error).message });
        }
      })();
      return;
    }

    const stored = readStoredTokens();
    if (!stored) {
      if (pendingDeepLinkRef.current) {
        try {
          beginGoogleLogin(pendingDeepLinkRef.current);
        } catch (err) {
          setStatus({ kind: "error", message: (err as Error).message });
        }
        return;
      }
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
    if (status.profile !== undefined) return;
    const session = signerSessionRef.current;
    if (!session) return;
    let cancelled = false;
    (async () => {
      const profile = await fetchProfile(session.pubky, session.publicKeyZ32);
      if (cancelled) return;
      setStatus((prev) =>
        prev.kind === "unlocked" && prev.pubkyZ32 === session.publicKeyZ32
          ? { ...prev, profile }
          : prev,
      );
    })();
    return () => {
      cancelled = true;
    };
  }, [status]);

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

  const handleDownloadRecovery = () => {
    setBackupError(null);
    const session = signerSessionRef.current;
    if (!session) {
      setBackupError("Signer not ready");
      return;
    }
    if (backupPass.length < 8) {
      setBackupError("Passphrase must be at least 8 characters.");
      return;
    }
    if (backupPass !== backupPass2) {
      setBackupError("Passphrases do not match.");
      return;
    }
    try {
      const bytes = session.keypair.createRecoveryFile(backupPass);
      const z32 = session.publicKeyZ32;
      const copy = new Uint8Array(bytes);
      const blob = new globalThis.Blob([copy], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `pubky-${z32.slice(0, 8)}.pkarr`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setBackupPass("");
      setBackupPass2("");
      resetIdle();
    } catch (err) {
      setBackupError((err as Error).message ?? "Failed to create recovery file");
    }
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
              Sign in with Google to unlock your passport. We&apos;ll request Drive app-storage access in the same step.
            </p>
            <button
              className="rounded bg-white px-4 py-2 text-sm font-medium text-black hover:bg-neutral-200"
              onClick={() => {
                try {
                  beginGoogleLogin(pendingDeepLinkRef.current);
                } catch (err) {
                  setStatus({ kind: "error", message: (err as Error).message });
                }
              }}
            >
              Sign in with Google
            </button>
            <p className="text-xs text-neutral-500">
              Your encrypted secret lives in a hidden, app-only folder. Not visible in your main Drive UI.
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
            <div className="rounded-lg border border-neutral-800 bg-neutral-900/50 p-6 space-y-4">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-3 min-w-0">
                  {status.profile?.imageDataUrl ? (
                    // eslint-disable-next-line @next/next/no-img-element
                    <img
                      src={status.profile.imageDataUrl}
                      alt=""
                      className="h-12 w-12 rounded-full object-cover bg-neutral-800 shrink-0"
                    />
                  ) : (
                    <div className="h-12 w-12 rounded-full bg-neutral-800 flex items-center justify-center text-sm font-medium text-neutral-300 shrink-0">
                      {(status.profile?.name ?? status.pubkyZ32).slice(0, 2).toUpperCase()}
                    </div>
                  )}
                  <div className="min-w-0">
                    <h2 className="text-lg font-semibold truncate">
                      {status.profile?.name ?? "Your Pubky"}
                    </h2>
                    <span className="text-xs uppercase tracking-wide text-neutral-400">
                      {status.profile?.name ? "Pubky identifier" : "Public key"}
                    </span>
                  </div>
                </div>
                <div className="flex flex-col items-end gap-1 shrink-0">
                  <button
                    className="text-xs text-neutral-400 hover:text-neutral-200"
                    onClick={signOut}
                  >
                    Sign out
                  </button>
                  {emailRef.current && (
                    <span className="text-[10px] text-neutral-500 truncate max-w-[180px]">
                      {emailRef.current}
                    </span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <pre
                  className={`flex-1 break-all whitespace-pre-wrap rounded bg-black/40 font-mono text-neutral-300 ${
                    status.profile?.name ? "text-xs p-2" : "text-sm p-3"
                  }`}
                >
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
                onClick={() => {
                  setShowBackup((s) => !s);
                  if (showBackup) {
                    setBackupPass("");
                    setBackupPass2("");
                    setBackupError(null);
                  }
                }}
              >
                {showBackup ? "Hide" : "Show"} backup · download recovery file
              </button>
              {showBackup && (
                <div className="mt-3 space-y-3">
                  <p className="text-xs text-neutral-500">
                    Encrypts your Pubky secret with a passphrase into a standard pubky recovery file.
                    Store it somewhere safe; anyone with the file and passphrase can recover your Pubky.
                  </p>
                  <input
                    type="password"
                    autoComplete="new-password"
                    className="w-full rounded border border-neutral-800 bg-black/40 p-2 text-sm placeholder:text-neutral-600 focus:border-neutral-600 focus:outline-none"
                    placeholder="Passphrase (min. 8 chars)"
                    value={backupPass}
                    onChange={(e) => {
                      setBackupPass(e.target.value);
                      if (backupError) setBackupError(null);
                    }}
                  />
                  <input
                    type="password"
                    autoComplete="new-password"
                    className="w-full rounded border border-neutral-800 bg-black/40 p-2 text-sm placeholder:text-neutral-600 focus:border-neutral-600 focus:outline-none"
                    placeholder="Confirm passphrase"
                    value={backupPass2}
                    onChange={(e) => {
                      setBackupPass2(e.target.value);
                      if (backupError) setBackupError(null);
                    }}
                  />
                  {backupError && (
                    <p className="text-xs text-red-400">{backupError}</p>
                  )}
                  <button
                    className="rounded bg-white px-4 py-2 text-sm font-medium text-black hover:bg-neutral-200 disabled:opacity-50"
                    onClick={handleDownloadRecovery}
                    disabled={!backupPass || !backupPass2}
                  >
                    Download recovery file
                  </button>
                </div>
              )}
            </div>

            <div className={showDebug ? "rounded-lg border border-neutral-800 bg-neutral-900/50 p-4" : ""}>
              <button
                className={
                  showDebug
                    ? "text-xs text-neutral-400 hover:text-neutral-200"
                    : "text-[11px] text-neutral-600 hover:text-neutral-400 underline-offset-2 hover:underline"
                }
                onClick={() => setShowDebug((s) => !s)}
              >
                {showDebug ? "Hide debug" : "Show debug…"}
              </button>
              {showDebug && (
                <div className="mt-3 space-y-2">
                  <p className="text-xs text-neutral-500 break-all">
                    appDataFolder/{status.file.name} · id {status.file.id}
                  </p>
                  <pre className="break-all whitespace-pre-wrap rounded bg-black/40 p-3 font-mono text-xs">
                    {JSON.stringify(status.blob, null, 2)}
                  </pre>
                  <button
                    className="rounded bg-red-900/60 px-3 py-1.5 text-xs font-medium text-red-200 hover:bg-red-900 disabled:opacity-50"
                    disabled={wiping}
                    onClick={() => {
                      if (window.confirm("Delete passport from Drive and revoke Google access? This cannot be undone.")) {
                        void wipeEverything();
                      }
                    }}
                  >
                    {wiping ? "Wiping…" : "Wipe now (no confirm)"}
                  </button>
                </div>
              )}
            </div>

            <div className={showWipe ? "rounded-lg border border-red-900/60 bg-red-950/20 p-4" : ""}>
              <button
                className={
                  showWipe
                    ? "text-xs text-red-300 hover:text-red-200"
                    : "text-[11px] text-neutral-600 hover:text-neutral-400 underline-offset-2 hover:underline"
                }
                onClick={() => {
                  setShowWipe((s) => !s);
                  if (showWipe) {
                    setWipeConfirm("");
                    setWipeError(null);
                  }
                }}
              >
                {showWipe ? "Hide danger zone" : "Delete everything…"}
              </button>
              {showWipe && (
                <div className="mt-3 space-y-3">
                  <p className="text-xs text-red-200/80">
                    Deletes <code>passport.json</code> from your Google Drive app folder, revokes this app&apos;s Google access, and signs you out. Your Pubky public key will still exist on the network, but the secret that controls it will be gone forever unless you have a recovery file.
                  </p>
                  <p className="text-xs text-neutral-400">
                    Type <span className="font-mono text-red-300">DELETE</span> to confirm.
                  </p>
                  <input
                    type="text"
                    autoComplete="off"
                    className="w-full rounded border border-red-900/60 bg-black/40 p-2 text-sm placeholder:text-neutral-600 focus:border-red-700 focus:outline-none"
                    placeholder="DELETE"
                    value={wipeConfirm}
                    onChange={(e) => {
                      setWipeConfirm(e.target.value);
                      if (wipeError) setWipeError(null);
                    }}
                  />
                  {wipeError && <p className="text-xs text-red-400">{wipeError}</p>}
                  <button
                    className="rounded bg-red-700 px-4 py-2 text-sm font-medium text-white hover:bg-red-600 disabled:opacity-40"
                    disabled={wipeConfirm !== "DELETE" || wiping}
                    onClick={() => void wipeEverything()}
                  >
                    {wiping ? "Wiping…" : "Delete passport and revoke access"}
                  </button>
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
  authStatus,
  onApprove,
  onDeny,
  onDismiss,
}: {
  request: ParsedAuthRequest;
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
