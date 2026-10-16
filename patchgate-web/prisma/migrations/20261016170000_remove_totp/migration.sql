-- Local sign-in is password-only by design (TOTP removed): strong passwords + lockout + session rules apply;
-- banks that need MFA use their SSO (AUTH_MODE=oidc), where the IdP enforces it.
-- Pending TOTP sign-in steps (VERIFY / ENROLL) die; the forced password-change step (PASSWORD) stays valid.
DELETE FROM "AuthChallenge" WHERE "kind" <> 'PASSWORD';
ALTER TABLE "AuthChallenge" DROP COLUMN IF EXISTS "pendingSecretEnc";

-- Stored authenticator secrets and replay counters are no longer used: drop them (data and columns).
ALTER TABLE "User" DROP COLUMN IF EXISTS "totpSecretEnc",
                   DROP COLUMN IF EXISTS "totpEnabled",
                   DROP COLUMN IF EXISTS "totpLastStep";
