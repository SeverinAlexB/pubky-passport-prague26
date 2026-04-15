import type { Keypair, Signer, Pubky } from "@synonymdev/pubky";

type PubkyModule = typeof import("@synonymdev/pubky");

let pubkyModulePromise: Promise<PubkyModule> | null = null;

export function loadPubky(): Promise<PubkyModule> {
  if (!pubkyModulePromise) {
    pubkyModulePromise = import("@synonymdev/pubky");
  }
  return pubkyModulePromise;
}

export const DEFAULT_HOMESERVER_Z32 =
  process.env.NEXT_PUBLIC_DEFAULT_HOMESERVER ??
  "8um71us3fyw6h8wbcxb5ar3rwusy1a6u49956ikzojg3gcwd1dty";

export type PubkySession = {
  keypair: Keypair;
  pubky: Pubky;
  signer: Signer;
  publicKeyZ32: string;
};

export async function createSigner(secret: Uint8Array): Promise<PubkySession> {
  const mod = await loadPubky();
  const keypair = mod.Keypair.fromSecret(secret);
  const pubky = new mod.Pubky();
  const signer = pubky.signer(keypair);
  return {
    keypair,
    pubky,
    signer,
    publicKeyZ32: keypair.publicKey.z32(),
  };
}

export type PubkyProfile = {
  name?: string;
  /** Data URL ready for <img src>, resolved from the homeserver blob chain. */
  imageDataUrl?: string;
};

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(
      null,
      Array.from(bytes.subarray(i, i + chunk)),
    );
  }
  return btoa(binary);
}

async function resolveImage(pubky: Pubky, imageUri: string): Promise<string | undefined> {
  try {
    const fileRecord = await pubky.publicStorage.getJson(imageUri as `pubky://${string}/pub/${string}`);
    if (!fileRecord || typeof fileRecord !== "object") return undefined;
    const src = typeof fileRecord.src === "string" ? fileRecord.src : undefined;
    const contentType =
      typeof fileRecord.content_type === "string" ? fileRecord.content_type : "image/*";
    if (!src) return undefined;
    const bytes = await pubky.publicStorage.getBytes(src as `pubky://${string}/pub/${string}`);
    return `data:${contentType};base64,${bytesToBase64(bytes)}`;
  } catch {
    return undefined;
  }
}

export async function fetchProfile(
  pubky: Pubky,
  publicKeyZ32: string,
): Promise<PubkyProfile | null> {
  try {
    const address = `pubky://${publicKeyZ32}/pub/pubky.app/profile.json` as const;
    const raw = await pubky.publicStorage.getJson(address);
    if (!raw || typeof raw !== "object") return null;
    const name = typeof raw.name === "string" ? raw.name.trim() : undefined;
    const imageUri =
      typeof raw.image === "string" && raw.image.startsWith("pubky://") ? raw.image : undefined;
    const imageDataUrl = imageUri ? await resolveImage(pubky, imageUri) : undefined;
    if (!name && !imageDataUrl) return null;
    return { name, imageDataUrl };
  } catch {
    return null;
  }
}

export type Capability = {
  path: string;
  perms: string;
  read: boolean;
  write: boolean;
};

export type ParsedAuthRequest =
  | {
      kind: "signin";
      raw: string;
      relay: string;
      capabilities: Capability[];
    }
  | {
      kind: "signup";
      raw: string;
      relay: string;
      capabilities: Capability[];
      homeserverZ32: string;
      signupToken?: string;
    };

function parseCaps(caps: string): Capability[] {
  return caps
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const sep = entry.lastIndexOf(":");
      if (sep === -1) {
        return { path: entry, perms: "", read: false, write: false };
      }
      const path = entry.slice(0, sep);
      const perms = entry.slice(sep + 1);
      return {
        path,
        perms,
        read: perms.includes("r"),
        write: perms.includes("w"),
      };
    });
}

export async function parseAuthRequest(input: string): Promise<ParsedAuthRequest> {
  const raw = input.trim();
  if (!raw) throw new Error("Auth URL is empty");
  if (!raw.toLowerCase().startsWith("pubkyauth:")) {
    throw new Error("Not a pubkyauth:// URL");
  }

  const mod = await loadPubky();

  try {
    const dl = mod.SignupDeepLink.parse(raw);
    return {
      kind: "signup",
      raw,
      relay: dl.baseRelayUrl,
      capabilities: parseCaps(dl.capabilities),
      homeserverZ32: dl.homeserver.z32(),
      signupToken: dl.signupToken,
    };
  } catch {
    // not a signup deeplink — try signin
  }

  try {
    const dl = mod.SigninDeepLink.parse(raw);
    return {
      kind: "signin",
      raw,
      relay: dl.baseRelayUrl,
      capabilities: parseCaps(dl.capabilities),
    };
  } catch (err) {
    throw new Error(`Invalid pubkyauth URL: ${(err as Error).message ?? err}`);
  }
}

export async function performApproval(
  signer: Signer,
  parsed: ParsedAuthRequest,
  opts: { defaultHomeserverZ32: string; alreadyEnsured: boolean },
): Promise<void> {
  const mod = await loadPubky();

  if (parsed.kind === "signup") {
    const hs = mod.PublicKey.from(parsed.homeserverZ32);
    await signer.signup(hs, parsed.signupToken ?? null);
  } else if (!opts.alreadyEnsured) {
    try {
      await signer.signinBlocking();
    } catch {
      const hs = mod.PublicKey.from(opts.defaultHomeserverZ32);
      await signer.signup(hs, null);
    }
  }

  await signer.approveAuthRequest(parsed.raw);
}

export function relayHost(relay: string): string {
  try {
    return new URL(relay).host;
  } catch {
    return relay;
  }
}
