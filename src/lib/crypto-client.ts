import { base64ToBytes, bytesToBase64 } from "./base64";

export interface Blob {
  v: 1;
  iv: string;
  ct: string;
}

export async function importWrappingKey(keyB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    base64ToBytes(keyB64) as BufferSource,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

export async function encryptSecret(wrapKey: CryptoKey, secret: Uint8Array): Promise<Blob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    wrapKey,
    secret as BufferSource,
  );
  return { v: 1, iv: bytesToBase64(iv), ct: bytesToBase64(new Uint8Array(ct)) };
}

export async function decryptSecret(wrapKey: CryptoKey, blob: Blob): Promise<Uint8Array> {
  if (blob.v !== 1) throw new Error(`unsupported blob version: ${blob.v}`);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(blob.iv) as BufferSource },
    wrapKey,
    base64ToBytes(blob.ct) as BufferSource,
  );
  return new Uint8Array(plain);
}

export function wipe(bytes: Uint8Array | null): void {
  if (bytes) bytes.fill(0);
}
