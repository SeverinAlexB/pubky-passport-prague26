# Passport Webapp — Design

A webapp where the user signs in with Google, and a private/public keypair tied to their Google account is stored encrypted in Google Drive. The webapp only has access to the keypair during an active session.

## Goals

- Login with Google is the only user-visible step (lowest UX friction).
- Keypair is tied to the Google account.
- By default (logged out), the webapp cannot access the keypair.
- During a session, the webapp holds the decrypted key in memory only, for a short time.
- Neither Google alone nor our server alone can decrypt the keypair.

## Threat model

| Who has what | Can decrypt? |
|---|---|
| Google (encrypted blob only) | ❌ no wrapping key |
| Our server (secret only) | ❌ no blob |
| Attacker with server dump | ❌ no blobs |
| Attacker with Drive/Takeout dump | ❌ no wrapping key |
| Both colluding / both breached | ✅ |
| Attacker with a live stolen Google session | ✅ (same access the user has) |

Zero-knowledge against **any single party** — but not against the user themselves, and not against a split-trust collusion. That is acceptable.

## Architecture

```
┌──────────────┐       ┌───────────────┐       ┌──────────────────────┐
│   Browser    │       │   Our server  │       │  Google Drive        │
│  (webapp)    │       │               │       │  (appDataFolder)     │
└──────┬───────┘       └───────┬───────┘       └──────────┬───────────┘
       │                       │                          │
       │ 1. Google OAuth (ID + access tokens)             │
       │─────────────────────────────────────────────────>│
       │                       │                          │
       │ 2. POST /wrapping-key (Bearer id_token)          │
       │──────────────────────>│                          │
       │                       │ verify id_token,         │
       │                       │ extract sub,             │
       │                       │ HKDF(secret, sub)        │
       │ 3. { key: base64 }    │                          │
       │<──────────────────────│                          │
       │                                                  │
       │ 4. GET/PUT encrypted blob in appDataFolder       │
       │<────────────────────────────────────────────────>│
       │                                                  │
       │ 5. Decrypt in memory with WebCrypto (non-extractable)
       │ 6. Clear on logout / idle / tab close
```

Two gates must pass to decrypt:

1. **Google login** — grants access token for `drive.appdata` → can fetch the blob.
2. **Server-held secret** — needed to derive the wrapping key → can decrypt the blob.

## Storage: Google Drive `appDataFolder`

- OAuth scope: `https://www.googleapis.com/auth/drive.appdata`
- Per-(OAuth client × Google account) hidden folder, invisible in the user's Drive UI.
- Counts against the user's Drive quota (trivially).
- Deleted if the user revokes the app in their Google account settings — doubles as a "burn my passport" flow.
- **Included in Google Takeout** — this is the reason encryption at rest matters here.

## Wrapping key derivation

Use **HKDF-SHA256**, not `SHA256(secret || sub)` (avoids length-extension, supports versioning and domain separation).

```js
// Node / server-side
import { hkdfSync } from "node:crypto";

const wrappingKey = hkdfSync(
  "sha256",
  serverSecret,           // IKM — from env var or KMS, never in repo
  "passport-v1",          // salt — version tag, enables rotation
  `wrap:${sub}`,          // info — binds to purpose + Google account
  32                      // 256-bit output
);
```

Properties:

- `sub` is a stable, opaque per-account identifier from the verified ID token.
- `sub` is **not a secret** — security rests entirely on `serverSecret`.
- Different user → different key. Same user across reinstalls → same key.

## The `/wrapping-key` endpoint

```
POST /wrapping-key
Authorization: Bearer <google_id_token>
```

Server logic:

1. **Verify the ID token** against Google's JWKS (`https://www.googleapis.com/oauth2/v3/certs`).
   - Check signature, `iss` (accounts.google.com), `aud` (our client ID), `exp`.
   - Use `google-auth-library` or equivalent — do not hand-roll JWT verification.
2. Extract `sub`.
3. Derive wrapping key via HKDF as above.
4. Return `{ key: base64(wrappingKey), version: "v1" }`.

**Critical**: verify the **ID token**, not the access token. An access token alone doesn't prove identity.

**Rate-limit** this endpoint. It is effectively an oracle that returns a per-user key given a valid Google session — limits + anomaly detection give us a chance to notice session theft.

## Blob format (stored in `appDataFolder`)

```json
{
  "v": 1,
  "iv": "base64(12 bytes)",
  "ct": "base64(AES-GCM ciphertext of PKCS8 private key)",
  "publicKey": { "...JWK..." }
}
```

- Cipher: AES-256-GCM.
- `v` allows future migration without breaking old blobs.
- Public key stored alongside for convenience (also available without decryption).

## Client flow

### First login (enrollment)

```js
// 1. Google Identity Services → access token + id token
const { access_token, id_token } = await googleLogin();

// 2. Get wrapping key from our server
const { key: wrapB64 } = await fetch("/wrapping-key", {
  method: "POST",
  headers: { Authorization: `Bearer ${id_token}` }
}).then(r => r.json());
const wrapKey = await crypto.subtle.importKey(
  "raw", b64decode(wrapB64),
  { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
);

// 3. Generate keypair in browser
const kp = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true, ["sign", "verify"]
);
const pkcs8 = await crypto.subtle.exportKey("pkcs8", kp.privateKey);

// 4. Encrypt
const iv = crypto.getRandomValues(new Uint8Array(12));
const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrapKey, pkcs8);

// 5. Upload to appDataFolder
await driveUpload(access_token, {
  v: 1,
  iv: b64(iv),
  ct: b64(ct),
  publicKey: await crypto.subtle.exportKey("jwk", kp.publicKey)
});
```

### Subsequent logins

```js
const { access_token, id_token } = await googleLogin();
const { key: wrapB64 } = await fetchWrappingKey(id_token);
const wrapKey = await importRawAesKey(wrapB64);

const blob = await driveDownload(access_token); // appDataFolder → first file
const pkcs8 = await crypto.subtle.decrypt(
  { name: "AES-GCM", iv: b64decode(blob.iv) },
  wrapKey,
  b64decode(blob.ct)
);

// Re-import as NON-EXTRACTABLE so in-page code can't serialize it back out
const privateKey = await crypto.subtle.importKey(
  "pkcs8", pkcs8,
  { name: "ECDSA", namedCurve: "P-256" },
  false,                  // ← key hygiene
  ["sign"]
);
```

### Session hygiene

- Store access token in `sessionStorage`, never `localStorage`.
- Do **not** request offline access / refresh tokens — let the ~1h token expiry end the session.
- Import wrapping key and private key as **non-extractable** `CryptoKey` objects.
- Clear in-memory state on:
  - `beforeunload` / tab close
  - Idle timeout (5 min suggested)
  - Explicit logout
  - Document visibility change (optional stricter policy)

```js
let privateKey = null;
let idleTimer;
const wipe = () => {
  privateKey = null;
  sessionStorage.clear();
};
const resetIdle = () => {
  clearTimeout(idleTimer);
  idleTimer = setTimeout(wipe, 5 * 60 * 1000);
};
window.addEventListener("beforeunload", wipe);
["mousemove", "keydown", "click"].forEach(e =>
  window.addEventListener(e, resetIdle)
);
```

## Key rotation

Server-secret rotation path is baked in via the `version` field:

1. Add `serverSecret_v2`; HKDF salt becomes `"passport-v2"`.
2. `/wrapping-key` endpoint returns a key for whichever version the client requests (or the latest).
3. On next login, client detects `blob.v === 1`, fetches v1 key, decrypts, re-encrypts with v2, uploads `{ v: 2, ... }`.
4. After all users have migrated (or a deadline), retire `serverSecret_v1`.

User-keypair rotation: generate new keypair, encrypt, overwrite blob. Old public key is gone unless separately archived.

## What this design does NOT protect against

Be explicit about these so we don't pretend otherwise:

- **Malicious or tampered webapp code during a session** — whatever code runs in the tab can read the decrypted key while it's in memory. Mitigate with strict CSP, Subresource Integrity on all scripts, and minimal third-party JS.
- **Stolen live Google session** — an attacker with the user's active Google session can log in, call `/wrapping-key`, and fetch the blob. Same authority as the user. Rate limits on the endpoint help detect this.
- **Compromise of `serverSecret` + Drive access** — by design, this combination decrypts everything. Protect the secret accordingly (env var or KMS, rotatable, audited).

## Open decisions

- [ ] Static-hosted webapp or server-rendered? (Static is fine; only the `/wrapping-key` endpoint needs a backend.)
- [ ] Idle timeout duration (default: 5 min).
- [ ] Keypair algorithm (default: ECDSA P-256; alternatives: Ed25519 via WebCrypto where supported, RSA-2048).
- [ ] Multi-device story: same keypair everywhere (current design) vs. per-device keypairs signed by a root.
- [ ] Key rotation cadence and trigger (user-initiated only, or scheduled).
