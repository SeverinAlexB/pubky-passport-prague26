import { hkdfSync } from "node:crypto";

type DeriveResult = { key: Buffer; version: string };
type Backend = (sub: string) => Promise<DeriveResult>;

const INFO = "passport-v1:wrap:";

function makeHkdfBackend(): Backend {
  const secret = process.env.SERVER_SECRET;
  if (!secret) throw new Error("SERVER_SECRET missing");
  return async (sub) => {
    const raw = hkdfSync("sha256", secret, "passport-v1", `wrap:${sub}`, 32);
    return { key: Buffer.from(raw), version: "v1-hkdf" };
  };
}

function makeKmsBackend(keyName: string): Backend {
  // Lazy require so the dependency isn't loaded in HKDF-only deployments.
  const { KeyManagementServiceClient } =
    require("@google-cloud/kms") as typeof import("@google-cloud/kms");
  const kms = new KeyManagementServiceClient();
  return async (sub) => {
    const [res] = await kms.macSign({
      name: keyName,
      data: Buffer.from(`${INFO}${sub}`),
    });
    if (!res.mac) throw new Error("kms macSign returned no mac");
    return { key: Buffer.from(res.mac), version: "v1-kms" };
  };
}

let backend: Backend | null = null;

function getBackend(): Backend {
  if (backend) return backend;
  const kmsKey = process.env.GCP_KMS_MAC_KEY;
  if (kmsKey) {
    console.info("[wrapping-key] backend: kms");
    backend = makeKmsBackend(kmsKey);
  } else if (process.env.SERVER_SECRET) {
    console.info("[wrapping-key] backend: hkdf");
    backend = makeHkdfBackend();
  } else {
    throw new Error("no wrapping-key backend configured (set GCP_KMS_MAC_KEY or SERVER_SECRET)");
  }
  return backend;
}

export async function deriveWrappingKey(sub: string): Promise<DeriveResult> {
  return getBackend()(sub);
}
