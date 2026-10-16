"use client";

interface ErrorPageProps {
  error: Error & { digest?: string };
  reset: () => void;
}

export default function ErrorPage({ error, reset }: ErrorPageProps) {
  const isAuth = error.name === "AuthError" || /signed in|SSO|user/i.test(error.message);
  return (
    <div className="space-y-3">
      <h1 className="text-xl font-semibold">
        {isAuth ? "Sign-in required" : "Something went wrong"}
      </h1>
      <p className="opacity-70">
        {isAuth ? "You must be signed in with a PatchGate account." : "Please try again."}
      </p>
      <button onClick={reset} className="rounded border px-3 py-1 text-sm">
        Retry
      </button>
    </div>
  );
}
