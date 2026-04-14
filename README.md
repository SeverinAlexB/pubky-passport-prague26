# Passport

A Next.js webapp that stores a 32-byte secret in your Google Drive, encrypted so neither Google alone nor this app's server alone can decrypt it. Login with Google; first login creates the secret, subsequent logins unlock it.

See `passport-webapp-design.md` for the design and threat model.

## Setup

### 1. Google Cloud Console

1. Open https://console.cloud.google.com, create/select a project.
2. **APIs & Services → Library** → enable **Google Drive API**.
3. **APIs & Services → OAuth consent screen**:
   - User type: External, status: Testing.
   - Add yourself as a test user (otherwise the `drive.appdata` scope triggers verification).
   - Add scopes: `.../auth/userinfo.email`, `openid`, and `.../auth/drive.appdata`.
4. **APIs & Services → Credentials → Create Credentials → OAuth client ID**:
   - Application type: Web application.
   - Authorized JavaScript origins: `http://localhost:3000`.
   - (No redirect URI needed — we use the implicit / GIS flow.)
5. Copy the client ID.

### 2. Environment

```bash
cp .env.local.example .env.local
```

Fill in:

```
NEXT_PUBLIC_GOOGLE_CLIENT_ID=<your web client ID>
GOOGLE_CLIENT_ID=<same web client ID>
SERVER_SECRET=<openssl rand -base64 48>
```

### 3. Run

```bash
pnpm install
pnpm dev
```

Open http://localhost:3000.

## How it works

1. `GoogleLogin` returns a Google **ID token** (identity proof).
2. `useGoogleLogin` with `drive.appdata` scope returns an **access token** (Drive API auth).
3. Client POSTs the ID token to `/api/wrapping-key`. Server verifies via `google-auth-library`, extracts `sub`, derives a per-user AES-256 key via `HKDF-SHA256(SERVER_SECRET, salt="passport-v1", info="wrap:${sub}")`, returns it. `sub` is used in-memory only, never logged.
4. Client queries Drive `appDataFolder` for `passport.json`:
   - If present: download, AES-GCM decrypt with the wrapping key → 32-byte secret.
   - If absent: `crypto.getRandomValues(32)` → AES-GCM encrypt → upload.
5. Secret is displayed as 64 hex chars (show/hide toggle). Wiped on sign-out, 5-minute idle timeout, or tab close.

## Verification

- Two different Google accounts produce two different secrets (per-user binding via `sub`).
- Same account across sessions produces the same secret (deterministic HKDF).
- `POST /api/wrapping-key` without or with an invalid Bearer token returns `401`.
- `appDataFolder` blob is hidden from the user's main Drive UI. Inspect via https://developers.google.com/drive/api/reference/rest/v3/files/list with `spaces=appDataFolder`.
- Revoking the app in Google account settings deletes the blob.

## Threat model note

Security rests on (a) the secrecy of `SERVER_SECRET` and (b) the integrity of your Google session. A party that holds both the server secret and the Drive blob can decrypt. The design document covers this in detail.
