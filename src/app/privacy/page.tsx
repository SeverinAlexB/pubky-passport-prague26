import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy · Passport",
  description: "How Passport handles your data.",
};

export default function PrivacyPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-12 text-sm leading-6 text-neutral-200">
      <h1 className="mb-2 text-2xl font-semibold text-white">Privacy Policy</h1>
      <p className="mb-8 text-neutral-400">Last updated: 15 April 2026</p>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">What Passport is</h2>
        <p>
          Passport is a browser-based signer for Pubky. It derives an encrypted secret that is stored in
          your own Google Drive and is only usable when you are signed in with your Google account and
          have granted this app access to its hidden app-data folder.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Data we handle</h2>
        <ul className="list-disc space-y-1 pl-5">
          <li>
            <strong>Google account identifier (<code>sub</code>) and email.</strong> Taken from the ID
            token issued by Google Sign-In. The <code>sub</code> is used as input to derive a per-user
            wrapping key on the server. Your email is displayed in the UI so you know which account is
            active.
          </li>
          <li>
            <strong>Google Drive access (app-data folder only).</strong> Passport requests the{" "}
            <code>drive.appdata</code> scope, which lets it read and write a hidden, app-specific folder.
            Passport cannot see, read, or modify any other file in your Drive.
          </li>
          <li>
            <strong>Encrypted passport blob.</strong> Your signing key is encrypted in your browser and
            stored as a single file in that hidden Drive folder. Passport never uploads the plaintext key
            anywhere.
          </li>
        </ul>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">What the server does</h2>
        <p className="mb-2">
          Passport&apos;s server has one job: verify your Google ID token and return a per-user wrapping
          key derived deterministically from your Google <code>sub</code>. The key is derived on every
          request and is not persisted.
        </p>
        <p>
          The server does not store your ID token, your email, your Drive contents, or your signing key.
          Standard request logs (timestamps, IP addresses, HTTP status) may be retained transiently by
          the hosting infrastructure for operational and security purposes.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">What we do not do</h2>
        <ul className="list-disc space-y-1 pl-5">
          <li>No third-party analytics, advertising, or tracking.</li>
          <li>No sale or sharing of your data.</li>
          <li>No access to Drive files outside the app-data folder.</li>
          <li>No server-side storage of user profiles, keys, or blobs.</li>
        </ul>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Google API Services disclosure</h2>
        <p>
          Passport&apos;s use and transfer of information received from Google APIs adheres to the{" "}
          <a
            className="underline"
            href="https://developers.google.com/terms/api-services-user-data-policy"
            target="_blank"
            rel="noopener noreferrer"
          >
            Google API Services User Data Policy
          </a>
          , including the Limited Use requirements.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Revoking access</h2>
        <p>
          You can revoke Passport&apos;s access at any time at{" "}
          <a
            className="underline"
            href="https://myaccount.google.com/permissions"
            target="_blank"
            rel="noopener noreferrer"
          >
            myaccount.google.com/permissions
          </a>
          . You can also delete the encrypted blob directly from the hidden app-data folder via the
          Drive API; revoking access alone does not delete existing files.
        </p>
      </section>

      <section>
        <h2 className="mb-2 text-lg font-semibold text-white">Contact</h2>
        <p>
          Questions about this policy: <a className="underline" href="mailto:privacy@buhlerlabs.com">privacy@buhlerlabs.com</a>.
        </p>
      </section>
    </main>
  );
}
