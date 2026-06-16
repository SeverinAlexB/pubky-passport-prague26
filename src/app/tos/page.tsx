import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service · Passport",
  description: "Terms for using Passport.",
};

export default function TermsPage() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-12 text-sm leading-6 text-neutral-200">
      <h1 className="mb-2 text-2xl font-semibold text-white">Terms of Service</h1>
      <p className="mb-8 text-neutral-400">Last updated: 16 June 2026</p>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Using Passport</h2>
        <p>
          Passport is a browser-based Pubky signer. By using Passport, you agree to use it only for
          lawful purposes and to comply with any terms that apply to services you connect to it,
          including Google Drive and Pubky services.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Your Responsibility</h2>
        <p>
          You are responsible for your Pubky identity, your Google account, and any recovery files or
          visible Drive backups you create. If you delete your encrypted key material or lose access to
          your Google account without another backup, your Pubky key may be unrecoverable.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Service Availability</h2>
        <p>
          Passport depends on third-party services, including Google Sign-In and Google Drive. We do
          not control those services and cannot guarantee uninterrupted access. Passport is provided on
          an experimental, best-effort basis and may change, pause, or stop at any time.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">No Warranty</h2>
        <p>
          Passport is provided as is, without warranties of any kind. We do not guarantee that it will
          be error-free, secure against every possible attack, or suitable for any specific purpose.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Limitation of Liability</h2>
        <p>
          To the maximum extent permitted by law, we are not liable for lost keys, lost data, loss of
          access, service interruptions, or indirect, incidental, or consequential damages arising from
          your use of Passport.
        </p>
      </section>

      <section className="mb-6">
        <h2 className="mb-2 text-lg font-semibold text-white">Changes</h2>
        <p>
          We may update these terms from time to time. Continued use of Passport after changes are
          posted means you accept the updated terms.
        </p>
      </section>

      <section>
        <h2 className="mb-2 text-lg font-semibold text-white">Contact</h2>
        <p>
          Questions about these terms: <a className="underline" href="mailto:privacy@buhlerlabs.com">privacy@buhlerlabs.com</a>.
        </p>
      </section>
    </main>
  );
}
