# GCP Cloud KMS setup for wrapping-key derivation

Passport's `/api/wrapping-key` endpoint can derive the per-user wrapping key via a Google Cloud KMS HMAC key (HSM-backed) instead of the in-process `SERVER_SECRET` HKDF fallback. This document walks through the one-time GCP setup.

Backend selection is done by env var (`src/lib/wrapping-key.ts`):

- `GCP_KMS_MAC_KEY` set → KMS backend.
- Else `SERVER_SECRET` set → local HKDF backend.
- Else → the endpoint returns 500.

When both are set, KMS wins.

---

## Prerequisites

- A GCP project with billing enabled (Cloud KMS is paid: HSM key ~$1/month + $0.03 per 10,000 MAC operations).
- For the CLI walkthrough: `gcloud` installed and authenticated (`gcloud auth login`).
- For the Console walkthrough: just a browser signed into your GCP account.

---

# Setup via the Cloud Console (web UI)

Each step links to the relevant Console page. Where the Console wording differs from the CLI equivalent, the Console label is in **bold**.

## 1. Pick / create a project and enable the API (Console)

- **Create / select project**: [console.cloud.google.com/projectcreate](https://console.cloud.google.com/projectcreate) → name it e.g. `passport-kms-prod`. Make sure a billing account is linked (Billing → Link a billing account).
- **Enable Cloud KMS**: go to [Cloud KMS in the API Library](https://console.cloud.google.com/apis/library/cloudkms.googleapis.com) → **Enable**.

## 2. Create a key ring (Console)

- Open [Security → Key Management](https://console.cloud.google.com/security/kms).
- Click **+ Create key ring**.
- **Key ring name**: `passport`.
- **Location type**: *Region*. **Region**: a regional one close to your server (e.g. `europe-west1`). Note: `global` does not support HSM — leave it unselected.
- **Create**.

## 3. Create the HMAC MAC key (Console)

- On the newly-created key ring page, click **+ Create key**.
- **What type of key do you want to create?** → *Generated key*.
- **Key name**: `wrapping-key`.
- **Protection level**: **HSM**.
- **Key material**: *Generated key*.
- **Purpose**: **MAC**.
- **Algorithm**: **HMAC SHA-256**.
- **Key rotation period**: leave as-is (rotation complicates migration — see operational notes below).
- **Create**.

Open the new key → **Versions** tab → click the three-dot menu next to **Version 1** → **Copy resource name**. This is your `GCP_KMS_MAC_KEY` value (should look like `projects/…/cryptoKeyVersions/1`).

## 4. Create a service account (Console)

- [IAM & Admin → Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts) → **+ Create service account**.
- **Service account name**: `passport-server`.
- **Description**: `Passport server (wrapping-key derivation)`.
- **Create and continue** → skip the "Grant this service account access to project" step (we grant access at the key level, not project level) → **Done**.
- Copy the service account email (format: `passport-server@<project>.iam.gserviceaccount.com`).

## 5. Grant least-privilege access on the key (Console)

Grant on the **key**, not the ring or project, so the account can only sign with this one key.

- [Security → Key Management](https://console.cloud.google.com/security/kms) → click your key ring → click the checkbox next to **wrapping-key** (do NOT open it).
- The **Info panel** opens on the right (if hidden, click **Show info panel** in the top bar).
- Click **+ Add principal**.
- **New principals**: paste the service account email.
- **Role**: search for and select **Cloud KMS CryptoKey Signer/Verifier** (`roles/cloudkms.signerVerifier`).
- **Save**.

## 6. Authenticate the server to GCP (Console)

### Option A — Cloud Run / GKE / GCE

- When creating/editing the service, set the **Service account** dropdown to `passport-server@…`. Application Default Credentials pick this up automatically — no extra config.
- Cloud Run path: [Cloud Run](https://console.cloud.google.com/run) → service → **Edit & deploy new revision** → **Security** → **Service account** → pick `passport-server`.

### Option B — Vercel / Fly / other PaaS (Workload Identity Federation)

No static secrets. The server authenticates to GCP using its platform-issued OIDC token.

1. [IAM & Admin → Workload Identity Federation](https://console.cloud.google.com/iam-admin/workload-identity-pools) → **+ Create pool**.
   - **Name**: `passport-pool`. **Continue**.
   - **Provider type**: *OpenID Connect (OIDC)*.
   - **Provider name**: `vercel` (or your platform).
   - **Issuer URL**: the platform's OIDC issuer (e.g. `https://oidc.vercel.com/<org>`).
   - **Attribute mapping**: `google.subject = assertion.sub`.
   - **Continue** → **Save**.
2. Back on the pool page → **Grant access** → **Grant access using Service Account impersonation** → pick `passport-server@…` → select principals as needed → **Save**.
3. On the pool's provider page, click **Download config** to get the WIF credential-config JSON. Drop the contents into your deploy platform as a secret (platform-specific variable name).

### Option C — Service-account JSON key (quick & ugly)

- [IAM & Admin → Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts) → click `passport-server` → **Keys** tab → **Add key** → **Create new key** → **JSON** → **Create**. A JSON file downloads.
- On the server, store it securely and set `GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json`.
- Reintroduces a long-lived static secret on the server; use only if WIF isn't available.

## 7. Local dev authentication (Console step — n/a)

There is no Console path for local-dev ADC. Run on your machine:

```bash
gcloud auth application-default login
```

If you want to impersonate the service account locally instead of using your user identity, also run:

```bash
gcloud config set auth/impersonate_service_account passport-server@<project>.iam.gserviceaccount.com
```

## 8. Wire it into the app

Set in `.env.local` (dev) or your platform's secret manager (prod):

```
GCP_KMS_MAC_KEY=<paste resource name copied in step 3>
```

Leave `SERVER_SECRET` unset in prod. You can keep it locally as a fallback (KMS still wins if both are set).

## 9. Smoke test from the Console

- [Security → Key Management](https://console.cloud.google.com/security/kms) → your key ring → **wrapping-key** → **Versions** tab.
- Click the three-dot menu next to Version 1 → **Try this key** (or use the **MAC sign** pane if available).
- **Data to sign (input)**: paste `passport-v1:wrap:test-sub`.
- **Sign** → the Console returns a 32-byte MAC in base64.
- If the button is greyed out or returns a 403, your user account is missing `roles/cloudkms.signerVerifier` on the key — add it the same way as step 5 (for your user email, not the service account). Note: this tests *your* access, not the service account's; a CLI smoke test while impersonating the service account (step 7) is more meaningful for prod readiness.

## 10. Enable audit logging (Console)

By default, Cloud KMS **data-access** logs (including `MacSign`) are disabled.

- [IAM & Admin → Audit Logs](https://console.cloud.google.com/iam-admin/audit).
- In the service list, check **Cloud Key Management Service (KMS) API**.
- In the **Data Access audit logs configuration** panel on the right, tick **Data Read** and **Data Write**.
- **Save**.

Verify by making a `MacSign` request, then opening [Logs Explorer](https://console.cloud.google.com/logs/query) and filtering on `resource.type="cloudkms_crypto_key"`.

---

# Setup via `gcloud` CLI

## 1. Pick / create a project and enable the API

```bash
# If creating new:
gcloud projects create passport-kms-prod --name="Passport KMS"
gcloud config set project passport-kms-prod

# Enable the KMS API:
gcloud services enable cloudkms.googleapis.com
```

## 2. Create a key ring

Pick a **regional** location close to where the Next.js server runs (e.g. `us-central1`, `europe-west1`). `global` does not support HSM protection.

```bash
gcloud kms keyrings create passport \
  --location=europe-west1
```

## 3. Create the HMAC MAC key (HSM-backed)

```bash
gcloud kms keys create wrapping-key \
  --location=europe-west1 \
  --keyring=passport \
  --purpose=mac \
  --default-algorithm=hmac-sha256 \
  --protection-level=hsm
```

Confirm:

```bash
gcloud kms keys describe wrapping-key \
  --location=europe-west1 --keyring=passport
# purpose: MAC, protectionLevel: HSM, algorithm: HMAC_SHA256
```

Grab the full key-version resource path (you'll need this for `GCP_KMS_MAC_KEY`):

```bash
gcloud kms keys versions list \
  --key=wrapping-key --keyring=passport --location=europe-west1 \
  --format="value(name)"
# → projects/passport-kms-prod/locations/europe-west1/keyRings/passport/cryptoKeys/wrapping-key/cryptoKeyVersions/1
```

## 4. Create a service account for the server

```bash
gcloud iam service-accounts create passport-server \
  --display-name="Passport server (wrapping-key derivation)"
```

## 5. Grant least-privilege access on the key

Use `roles/cloudkms.signerVerifier` scoped to the specific key (not the ring or project). This grants `MacSign` / `MacVerify` and nothing else.

```bash
SA_EMAIL="passport-server@passport-kms-prod.iam.gserviceaccount.com"

gcloud kms keys add-iam-policy-binding wrapping-key \
  --location=europe-west1 --keyring=passport \
  --member="serviceAccount:${SA_EMAIL}" \
  --role="roles/cloudkms.signerVerifier"
```

## 6. Authenticate the server to GCP

Pick one based on where Passport is hosted.

### Option A — Cloud Run / GKE / GCE (recommended)

Attach the service account directly; Application Default Credentials (ADC) works with zero client-side config.

```bash
gcloud run deploy passport \
  --service-account=${SA_EMAIL} \
  …other flags…
```

### Option B — Vercel / Fly / other PaaS: Workload Identity Federation

No static secrets. The server authenticates to GCP using its platform-provided OIDC token.

```bash
# Create a workload identity pool + OIDC provider:
gcloud iam workload-identity-pools create passport-pool --location=global
gcloud iam workload-identity-pools providers create-oidc vercel \
  --location=global --workload-identity-pool=passport-pool \
  --issuer-uri="https://oidc.vercel.com/<org>" \
  --attribute-mapping="google.subject=assertion.sub"

# Bind the pool to the service account:
gcloud iam service-accounts add-iam-policy-binding ${SA_EMAIL} \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/<num>/locations/global/workloadIdentityPools/passport-pool/*"
```

Then drop the WIF credential-config JSON into the deploy env (platform-specific).

### Option C — Quick and ugly: service-account JSON key

```bash
gcloud iam service-accounts keys create ./key.json \
  --iam-account=${SA_EMAIL}
# Mount key.json on the server and set:
#   GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
```

This reintroduces a long-lived static secret on the server and partly defeats the HSM benefit. Use only when WIF isn't available.

## 7. Local dev authentication

```bash
gcloud auth application-default login

# Optional: impersonate the service account instead of your user account:
gcloud config set auth/impersonate_service_account ${SA_EMAIL}
```

With ADC set up, `KeyManagementServiceClient` picks up credentials automatically — no code changes needed.

## 8. Wire it into the app

Set in `.env.local` (dev) or your platform's secret manager (prod):

```
GCP_KMS_MAC_KEY=projects/passport-kms-prod/locations/europe-west1/keyRings/passport/cryptoKeys/wrapping-key/cryptoKeyVersions/1
```

Leave `SERVER_SECRET` unset in prod. You can keep it locally as a fallback (KMS still wins if both are set).

## 9. Smoke test directly

Before running the app, verify your account can sign:

```bash
echo -n "passport-v1:wrap:test-sub" | \
  gcloud kms mac-sign \
    --key=wrapping-key --keyring=passport --location=europe-west1 \
    --input-file=- --mac-file=-
```

Should return 32 bytes of MAC. If this fails, fix IAM before running the server.

## 10. Enable audit logging

By default, Cloud KMS **data-access** logs (including `MacSign`) are disabled. Turn them on so every wrapping-key derivation is logged.

Console: IAM & Admin → Audit Logs → Cloud KMS → enable **Data Read** and **Data Write**.

Or via CLI — fetch the policy, add an `auditConfigs` entry, apply:

```bash
gcloud projects get-iam-policy passport-kms-prod --format=json > iam.json
# edit iam.json to add:
#   "auditConfigs": [
#     {
#       "service": "cloudkms.googleapis.com",
#       "auditLogConfigs": [
#         {"logType": "DATA_READ"},
#         {"logType": "DATA_WRITE"}
#       ]
#     }
#   ]
gcloud projects set-iam-policy passport-kms-prod iam.json
```

Verify afterwards by making a `MacSign` request and checking that an entry appears in **Logs Explorer** filtered on `resource.type="cloudkms_crypto_key"`.

---

## Operational notes

- **Migration:** the KMS backend produces a different 32-byte key than the HKDF backend for the same `sub`, so blobs encrypted under one backend cannot be decrypted under the other. Switching backends with existing users requires a re-encrypt-on-unlock migration (out of scope today).
- **Key rotation:** Cloud KMS supports multiple `cryptoKeyVersions`. To rotate, create a new version, but pin the server to a specific version via `GCP_KMS_MAC_KEY=…/cryptoKeyVersions/N`. Rotating breaks decryption of existing blobs unless `info` is versioned on the client side too.
- **Cost sanity check:** at ~10k MAC ops per day → $0.03/day + $1/mo for the key. Trivial.
- **Region pinning:** keep the KMS region on the same continent as the server to keep `macSign` round-trip under ~30 ms.
