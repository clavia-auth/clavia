# Design: sign-up, email verification and password reset

**Status:** built · **Date:** 2026-11-22

## 1. Summary

People can create their own account, prove their address, and set a new password when they have
forgotten theirs, from the sign-in pages, without an operator. All three build on what exists:
database connections (pools), the mailer, single-use handles in Redis, the send limits, and
`CompleteFirstFactor`.

### Goals

- **Sign-up** into a pool whose operator allows it, from the login page of an authorization
  request, returning to that request.
- **Email verification**: a link that proves the person controls the address, sent at sign-up
  and whenever a pool that requires a verified address meets an unverified account.
- **Password reset**: a link to set a new password, which also works as an invitation for an
  account an operator created without one.

### Not in scope

- Operator-triggered mail: built afterwards as `POST /api/v1/users/{user_id}/password-reset`,
  which reuses these flows (see the Management API document).
- Changing the address from the account pages, profile fields at sign-up, CAPTCHA, terms
  acceptance.

## 2. Decisions

| Topic | Decision | Why |
|---|---|---|
| Who may sign up | Per pool: `allow_sign_up` on a database connection, off by default | Opening registration is an operator's choice, connection by connection. Nothing changes for existing deployments |
| Verified address required | Per pool: `require_verified_email`, off by default | With it on, an unverified account cannot sign in with a password until it follows a link. This closes account squatting (registering someone else's address) |
| Which pool takes a sign-up | The application's first pool allowing it: the default pool if eligible, otherwise by name | Deterministic, and one form. Several open pools for one application is an unusual setup |
| Proof of address | A link, never a code | It may be opened on any device, later. A mail scanner's GET spends nothing: the page asks, a POST confirms |
| After verification | A **Sign in** button back to the login page, not signed in | A link proves the mailbox, not the password. Signing in from it would make the mailbox enough for a password account |
| After a reset | Every session ended, the address marked verified, back to the login page | A reset is what a person does when they fear someone else knows the password. The link proved the mailbox |
| A taken address at sign-up | The same "check your inbox" answer; the owner gets a notice instead of a link | The form never says whether an address is registered |
| An unknown address at reset | The same "check your inbox" answer; nothing is sent | No enumeration, and no mail to strangers |
| Links | 43-character tokens, stored as digests in Redis, claimed once with `GETDEL` | The existing handle pattern |
| A reset link after the password changed | Dead | The link carries a fingerprint of the password hash it was issued against |
| Mail unavailable | Sign-up into a pool requiring verification, and reset, are not offered | `ConnectionAccess`-style: hidden, not failing on use |

## 3. Settings

| Setting | Default | Meaning |
|---|---|---|
| `CLAVIA_VERIFICATION_LINK_LIFETIME` | `86400` | Seconds a verification link lives (`#[Range(600, 604800)]`) |
| `CLAVIA_RESET_LINK_LIFETIME` | `1800` | Seconds a reset link lives (`#[Range(300, 86400)]`) |
| `CLAVIA_ACCOUNT_EMAIL_SEND_LIMIT` | `5` | Account emails per hour, per address and per client address (`#[Range(1, 100)]`) |
| `CLAVIA_SIGN_UP_LIMIT` | `10` | Sign-ups per hour per client address (`#[Range(1, 1000)]`) |

## 4. Model

- **`Connection`** gains `allowsSignUp` and `requiresVerifiedEmail`, both refused on anything but
  a database connection. `Connection::pool()` takes them; `switched()` changes them.
  Migration `0024_self_service_accounts` adds the two columns, with a check that only a database
  connection may set either.
- **`Domain\Identity\AccountLink`**: what a link stands for, kept in Redis. Its `purpose`
  (`VerifyEmail`, `ResetPassword`), the account, the address it was sent to, the login state it
  came from (to return to it), and for a reset the fingerprint of the password hash.
  `AccountLink::stillMatches(User)` is the rule: the same address, an active account, and for a
  reset the same password hash.
- **`Application\Port\AccountLinkStore`**: `open(token, link, lifetime)`, `find(token)`,
  `claim(token)`. `Redis\RedisAccountLinkStore`, keys `account-link:<digest>`.
- **`Application\Authentication\EmailSendLimit`**: the passwordless send limit, generalised with a
  namespace, so passwordless and account mail count separately.
- **`ConnectionAccess::signUpPool(?Client)`** and **`requiresVerifiedEmail(ConnectionName)`**.
- **Events**: `Identity\Event\UserSignedUp` (`user.signed_up`), `Identity\Event\EmailVerified`
  (`user.email_verified`), `Identity\Event\PasswordReset` (`user.password_reset`), all in the
  Directory trail. `SessionEndReason::PasswordReset`; `SignInRefusal::EmailNotVerified`.

## 5. Flows

### 5.1 Sign-up

1. The login page shows **Create an account** when `signUpPool(client)` is not null, and, when
   that pool requires a verified address, when mail can be sent. The link carries the login
   page's handle.
2. `GET /auth/signup` shows email and password (`autocomplete="new-password"`) with the policy.
3. `POST /auth/signup` (CSRF) runs `SignUp`:
   - the pool is resolved again from the handle; none means refused;
   - the sign-up limit per client address; the password through `PasswordPolicy`;
   - **a taken address**: a notice is mailed to it ("someone tried to create an account with
     your address; sign in or reset your password"), within the send limit, and the answer is
     the same as for a new account;
   - **a new address**: the account is created (unverified, in the pool) with `UserSignedUp`, and
     a verification link mailed;
   - when the pool requires a verified address, the answer is **Check your inbox** and no session;
     otherwise `CompleteFirstFactor` signs the person in (`amr: pwd`), and the request resumes.

### 5.2 Email verification

- **Sending** (`SendVerificationLink`): within the send limit, a link to
  `https://auth.{domain}/auth/verify-email?token=…`, valid `CLAVIA_VERIFICATION_LINK_LIFETIME`.
- **Opening** (`GET`): a page with a **Confirm my address** button. Nothing is spent.
- **Confirming** (`POST`, `ConfirmEmail`): the link is claimed; `stillMatches()`; the account is
  marked verified, saved, and `EmailVerified` dispatched. The page then offers the way back: to
  the login page of the original request when it is still pending. The address is not put in
  that URL.
- **At password sign-in**: in a pool requiring a verified address, an unverified account with the
  *right* password is refused with `EmailVerificationRequired` (audited as `email_not_verified`),
  and a new link is sent. The answer only differs from a wrong password once the password is
  right, so it reveals nothing.

### 5.3 Password reset

1. The login page shows **Forgot your password?** under the password form when mail can be sent.
2. `POST /auth/password/forgot` (CSRF, `RequestPasswordReset`): within the send limit, every
   active account with that address in the application's pools gets a reset link. The answer is
   always the same page.
3. `GET /auth/password/reset?token=…`: a new-password form, the token in a hidden field. Nothing
   is spent.
4. `POST /auth/password/reset` (`ResetPassword`): the password through the policy first (a
   refusal keeps the link), then the link claimed and `stillMatches()`. The password is changed,
   the address marked verified, `PasswordReset` dispatched, and every session ended
   (`SessionEndReason::PasswordReset`, so back-channel logout runs). The page leads back to the
   login page of the original request when it is still pending.

## 6. Pages and mail

- Pages: `auth/signup`, `auth/check-inbox` (shared by sign-up and reset), `auth/verify-email`,
  `auth/email-verified`, `auth/password-forgot`, `auth/password-reset`, `auth/password-changed`.
  Every variable gets an `AuthPagesEscapingTest` case.
- Mail (`AccountMail`): the verification link, the reset link, and the taken-address notice. Plain
  text, the deployment's sender, no tracking.

## 7. Management API

`Connection` gains `allow_sign_up` and `require_verified_email` (create and update, database
connections only; 422 otherwise).

## 8. Security rules

- No form says whether an address has an account: sign-up, reset and verification answer alike.
- A link is single-use, short-lived, stored as its digest, spent only by a POST, and dead once the
  address or (for a reset) the password changes.
- Mail is limited per address and per client address; sign-ups per client address.
- A reset ends every session. Verification never signs anyone in.

## 9. Tests

Unit tests for `AccountLink`, `Connection`'s new rules and each use case; contract tests for
`AccountLinkStore` (in memory and Redis); acceptance tests for each flow through the pipeline,
including every refusal, the mail sent (`MailOutbox`), the audit events, and the Management API
fields against the contract.
