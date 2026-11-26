# Design: translated sign-in pages and mail

**Status:** proposed · **Date:** 2026-11-26 · **Issue:** clavia-auth/clavia#24 ·
**Specifications:** OpenID Connect Core 1.0 §3.1.2.1 (`ui_locales`), OpenID Connect Discovery 1.0 §3
(`ui_locales_supported`), RFC 9110 §12.5.4 (`Accept-Language`) and §8.5 (`Content-Language`), RFC 4647
§3.4 (lookup), BCP 47 (RFC 5646), ICU MessageFormat

## 1. Summary

Every word a person reads on `auth.{domain}` is English, written in templates, page classes and, for
mail and the consent screen's scope descriptions, in the application layer. A person whose language is
French signs in, approves a device or resets a password in English, and an application asking for
French with `ui_locales` is ignored.

This design puts every such word in a message catalogue, one per language, with English and French
first; chooses the language of each page and each mail from what the person, the application and the
browser say; and keeps the catalogues complete by test.

### Goals

- **Every page of `auth.*`** (sign-in, sign-up, second factor, passkeys, consent, device approval,
  passwordless, verification and reset, sign-out, error pages) in English and French, the `<html lang>`
  and `Content-Language` saying which.
- **Every mail** (verification, reset, invitation, the taken-address notice, the passwordless code and
  link, the second-factor enrolment notice) in the language of the person it concerns.
- **`ui_locales`** honoured, and announced in discovery (`ui_locales_supported`).
- **`Accept-Language`** honoured when nothing more specific is known.
- **A language is added by adding one catalogue file**, and the tests say what it lacks.

### Not in scope

- **Words an operator wrote**: a client's name, a connection's display name, an API's permission
  descriptions. They are shown as written, in one language.
- **What programs read**: OAuth `error_description` (RFC 6749 §5.2 makes it ASCII, for developers), the
  Management API's and SCIM's errors, logs, the audit trail. They stay English.
- **`claims_locales`** (OpenID Connect Core §5.2): claims in several languages. Nothing stores them.
- **The dashboard** (clavia-dashboard), which has its own pages and its own issue if it comes.
- **Right-to-left scripts**: the catalogue allows them, the stylesheet is not checked for them yet.
- **Translations beyond French.** The mechanism takes them; contributors bring them.

## 2. Decisions

| Topic | Decision | Why (alternatives rejected) |
|---|---|---|
| Message format | **ICU MessageFormat**, through `ext-intl`'s `MessageFormatter` (already in the image, ICU 78) | Plurals and selections done right per language ("0 compte" is singular in French, "0 accounts" plural in English), and the format translation tools (Weblate, Crowdin) know. Rejected: `sprintf` strings (no plurals, positional arguments translators reorder wrongly); gettext (`.po`, needs the gettext extension and compiled `.mo` files, plural rules per file) |
| Library | **None new.** A small adapter over `MessageFormatter` and `Locale` | `symfony/translation` would do it, with a dependency tree for what is a lookup and a format call; laminas-i18n likewise. The adapter is about a hundred lines and passes a contract test, as every adapter does |
| Catalogue files | **JSON, one per language**: `translations/en.json`, `translations/fr.json`, flat `"key": "ICU message"` | Data, not code: a translation contributed in a pull request cannot hide PHP, which a `return [...]` file could. Every translation tool reads flat JSON. Rejected: PHP arrays (executable), XLIFF (verbose for a few hundred messages) |
| Keys | **Dotted, by page or mail and role**: `login.title`, `login.submit`, `mail.reset.subject`, `error.not_found.heading` | Stable when the English changes; groups what a translator sees together. Rejected: the English text as key (gettext style): a typo fix in English would orphan every translation |
| Where words live | **Adapters only.** Pages: templates and page classes call the catalogue. Mail: the application says *which* mail, *to whom*, *in which language* and with *which values*; the catalogue words it | The application already holds the mail's English (`AccountMail`, `SignInMail`) and the consent screen's scope descriptions (`ScopeDescriptions`). Words are presentation; the application keeps intent. Rejected: a translator port the application calls with keys (puts message keys, a presentation concern, into use cases) |
| The port | **`Application\Port\Messages`**: `text(Language, MessageKey, array $values): string`, implemented by `Adapter\Secondary\Messages\IcuMessages`; the mail adapter and the page renderer both reach it as a port | Two adapters need the same catalogue (the HTTP pages, primary; mail rendering, secondary) and adapters never call each other (`CLAUDE.md`, rule 4) |
| Mail | **The `Mailer` port's `OutgoingMail` carries a `MailContent`** (which mail, its values) and a `Language` instead of a subject and a text. **`RenderedMailer`**, the port's one implementation (wrapped by `CountingMailer` as today), words it through `Messages` and hands a `RenderedMail` (subject, text) to the transport, now an interface of the mail adapter's own (`MailTransport`: `smtp`, `console`, `none`) | One place words every mail, and the transports keep sending text as they do; the console outbox shows the mail as it was sent |
| Language value | **`Domain\Shared\Language`**: a BCP 47 primary tag with an optional region, checked by syntax, never by `ext-intl` (the domain imports nothing). **`Languages`**: the ones offered, and the default | The domain must not import an extension. The adapter matches; the domain only holds what was chosen |
| Choosing a page's language | **In order**: the person's own choice (a `clavia_language` cookie, set by a switcher on every page) → the `ui_locales` of the authorization request the page serves → `Accept-Language` → the default. Each candidate matched against the offered languages by RFC 4647 §3.4 lookup (`fr-CA` → `fr`) | The person outranks the application, which outranks the browser: an application knows its user's choice better than a shared kiosk's browser does, and the person knows best. Rejected: `ui_locales` first (a person who switches to English on a French application's page must get English) |
| `ui_locales` across the sign-in | **Recorded on what holds the request** (`LoginState`, `PendingConsent`, the step-up and enrolment states), from the request as it arrived, pushed (PAR) or not | A held request resumes through its URL, but a pushed request's parameters are not in it; the pages between need the value without re-reading the request. Malformed tags are dropped, not refused: OpenID Connect makes `ui_locales` a hint, never an error |
| Choosing a mail's language | **The page's** when a person in a browser caused it (sign-up, forgot password, passwordless, enrolment); **the account's `locale` profile claim** matched to the offered languages when an operator did (the invitation and reset of `POST /api/v1/users/{id}/password-reset`); else the default | The person reading the page reads the mail a minute later; nobody's browser is involved in an operator's request, and the profile is the only signal there |
| Accept-Language parsing | **Our own**, RFC 9110 §12.5.4 with q-values, at most ten ranges read; `q=0` excludes | `Locale::acceptFromHttp()` returns the first tag only, ignoring q-values and the offered list |
| A missing message | **In the default language**: a bug, an exception (and a test fails first). **In another**: the default language's message, and a warning logged once per key and request | A page never breaks for a missing translation; a missing English one is never shipped |
| HTML in messages | **Never.** A message is text; templates escape it as today. Emphasis inside a sentence is split into messages around the emphasised value | Keeps `AuthPagesEscapingTest`'s guarantee and lets translators work without markup |
| The switcher | **A form in the page footer**, beside the colour-scheme toggle: `POST /auth/language`, a `clavia_language` cookie, back to the page (`LocalPath`). No CSRF token, as for the theme toggle: a `SameSite=Lax` cookie never rides a cross-site POST, and it changes only how this browser reads | A person on someone else's browser, or whose browser is set to a language they do not read, needs a way out |
| Discovery | **`ui_locales_supported`**: the offered languages | OpenID Connect Discovery 1.0 §3; it says what an application may ask for |

## 3. Settings

| Variable | Default | Meaning |
|---|---|---|
| `CLAVIA_LANGUAGES` | every shipped catalogue (`en fr`) | The languages offered, space-separated BCP 47 tags; each must have a catalogue |
| `CLAVIA_DEFAULT_LANGUAGE` | `en` | The language when nothing else matches; must be offered |

A language without a catalogue, or a default not offered, refuses to start (exit 78), checked by the
composition root, which knows the catalogue files (as `SamlKeyReferences` checks key references).

## 4. Model

**Domain**
- `Shared\Language`: a BCP 47 tag, primary language (2–3 letters) and optional region (`fr`, `pt-BR`),
  normalised (`fr-ca` → `fr-CA`); `fromString` throws `InvalidValue`.
- `Shared\Languages`: the offered list and the default; `has(Language)`.
- `OAuth2\UiLocales`: the well-formed tags of a `ui_locales` value, in order, at most ten; malformed
  tags dropped. Held by `LoginState`, `PendingConsent` and the step-up and enrolment states (all in
  Redis: no migration).

**Application**
- `Port\Messages`: `text(Language, MessageKey, array<string, string|int|float> $values): string`, and
  `languages(): Languages`.
- `Port\MailContent`: the seven mails `AccountMail` and `SignInMail` compose today (`Verification`,
  `Reset`, `Invitation`, `AddressTaken`, `SecondFactorEnrolled`, `PasswordlessCode`, `PasswordlessLink`),
  each with its values (a link, a code, a lifetime); `OutgoingMail` becomes `{to, MailContent, Language}`.
- `AccountMail` and `SignInMail` build `MailContent`, never words; each use case
  that mails takes the `Language` from its caller, or (operator's path) works it out from the account's
  profile `locale`.
- `ScopeDescriptions` gives way: the consent and device use cases return the scopes, and the page words
  the standard ones (`openid`, `profile`, `email`, `offline_access`); an API permission's description
  stays the operator's.
- `PasswordRejected` carries a reason (`PolicyRefused` with the bounds, `Breached`) instead of English.

**Adapters**
- `Secondary\Messages\IcuMessages`: loads a catalogue on first use per language, formats with
  `MessageFormatter`, falls back as §2 says. A double, `FakeMessages`, returns `key{values}` so use-case
  tests read without a catalogue; both pass `MessagesContract`.
- `Secondary\Mail\RenderedMailer`: the `Mailer` port; words a `MailContent` in its language and hands
  a `RenderedMail` to a `MailTransport`, the adapter's own interface, which `SmtpMailer`, `OutboxMailer`
  and `NoMailer` implement instead of the port.
- `Primary\Http\Shared\LanguageChoice`: the page's language from the cookie, the held request's
  `UiLocales`, `Accept-Language` and the default. `PageRenderer` sets `<html lang>`, `Content-Language`
  and the language the templates' `t()` helper uses.
- `translations/en.json`, `translations/fr.json`.

## 5. Flows

### 5.1 A page

1. The handler builds its `HtmlPage` as today, with message keys and values where it had sentences.
2. `LanguageChoice` decides: the `clavia_language` cookie if it names an offered language; else the
   held request's `UiLocales` (the login state, pending consent or step-up the page serves), first
   that matches; else `Accept-Language` by q-value, first that matches; else the default.
3. `PageRenderer` renders with that language: `t('login.submit')` in templates, `<html lang="fr">`,
   `Content-Language: fr`.

### 5.2 `ui_locales`

1. `/oauth2/authorize` (or `/oauth2/par`) reads `ui_locales` with the other parameters; malformed tags
   are dropped, the rest kept in order. It is never a reason to refuse.
2. When the request is held (sign-in, consent, step-up, enrolment on the way), its `UiLocales` is
   recorded on what holds it, and the pages read it there.
3. A resumed request carries the parameter as it came, so the next hold records it again.

### 5.3 A mail

1. A person in a browser: the handler passes the page's language to the use case, which builds the
   `MailContent` with it.
2. An operator (`SendPasswordLink`): the account's profile `locale`, matched to the offered languages
   by lookup; else the default.
3. `RenderedMailer` words subject and text from the catalogue; the transport sends them as today.

### 5.4 The switcher

`POST /auth/language` with `language` and `return_to`: an offered language sets `clavia_language`
(a year, `HttpOnly; SameSite=Lax`, `Path=/auth`); anything else is ignored. The browser goes back to
`return_to` validated as a `LocalPath`, or `/auth/login`.

## 6. Interfaces

- **Pages**: every page of `auth.*`, the same routes; a language switcher in the footer.
- **`POST /auth/language`**: new, as above.
- **Discovery**: `ui_locales_supported`.
- **Management API, SCIM, OAuth errors**: unchanged, English.
- **Dashboard**: no change.
- **The authorization server's document**: `ui_locales` among `/oauth2/authorize`'s parameters, and
  `ui_locales_supported` in the metadata.

## 7. Security rules

- **A translation is data.** Catalogues are JSON, read with `json_decode`, never included; a message
  is text, escaped where printed. A message holding HTML fails the catalogue test.
- **A language is chosen from a closed list.** Cookie, `ui_locales` and `Accept-Language` only ever
  select one of the offered languages; nothing they say reaches a path, a file name or a page
  unmatched.
- **No answer differs by language in what it reveals.** Sign-in, sign-up and reset refusals are the
  same message in each language, and the same status.
- **Values are never formatted as messages.** A value (an address, a code) is an argument to a
  message, never part of its pattern, so a value with ICU syntax in it is printed, not interpreted.
- **The switcher sets only how this browser reads**: no CSRF token is needed, as for the theme
  toggle, and its target is a `LocalPath`.

## 8. Tests

| Test | Proves |
|---|---|
| `LanguageTest`, `UiLocalesTest` (unit) | well-formed tags, normalisation, malformed tags dropped, at most ten |
| `AcceptLanguageTest` (unit) | q-values, `*`, `q=0`, ranges beyond ten ignored, lookup (`fr-CA` → `fr`) |
| `MessagesContract` (both the double and `IcuMessages`) | formatting, plurals, a missing key in the default language throws, in another falls back and logs |
| `CatalogueTest` | every language has exactly the default's keys; each message parses with `MessageFormatter` for its language; the same arguments in each; no HTML; every key the templates and classes use exists, and every key exists in some use |
| `TranslatedPagesTest` (acceptance) | each page in French by `Accept-Language`, by `ui_locales` (pushed and not), and by the switcher; precedence as §5.1; `<html lang>` and `Content-Language` |
| `AuthPagesEscapingTest` | every page with hostile values, in both languages |
| `TranslatedMailTest` (acceptance) | each mail in French when the page was; the operator's invitation in the profile's language |
| `DiscoveryTest` | `ui_locales_supported` |
| `SettingsTest`, `WiringTest` | an unknown or uncatalogued language refuses to start |

## 9. Slices

1. **The catalogue and the language of a page.** `Language`, `Languages`, `Messages` and `IcuMessages`
   with its double and contract, the settings, `LanguageChoice` from `Accept-Language` and the default,
   `<html lang>`, `Content-Language`, the templates' `t()`, `CatalogueTest`; the layout, the login page
   and the error pages in English and French. *Done when* the login page and the error pages answer
   `Accept-Language: fr` in French, and the catalogue test guards completeness.
2. **Every page.** The remaining templates and page classes, `ScopeDescriptions` and
   `PasswordRejected` worded by the adapter, `ExternalSignInMessages` keyed; French for all.
   *Done when* every page renders in French with no missing key, and `AuthPagesEscapingTest` runs in
   both languages.
3. **`ui_locales`.** `UiLocales`, recorded where requests are held (pushed ones included), the
   precedence, `ui_locales_supported` in discovery and in the authorization server's document.
   *Done when* an application asking `ui_locales=fr` gets French through sign-in, a second factor and
   consent, whatever the browser says.
4. **Mail.** `MailContent`, `RenderedMailer`, the mails' language as §5.3, French for all.
   *Done when* each mail is French when its page was, and an operator's invitation follows the
   account's profile.
5. **The switcher.** `POST /auth/language`, the cookie, its place first in the precedence.
   *Done when* a person can switch any page's language, and the choice outranks `ui_locales`.

## 10. Open questions

1. **Should a person's own choice outrank `ui_locales`?** OpenID Connect leaves the order to the server.
   *Recommendation: yes*, as §2: the switcher exists for a person the application or the browser got
   wrong, and it would be useless otherwise.
2. **Is the switcher in scope for #24?** The issue asks for `ui_locales` and `Accept-Language` only.
   *Recommendation: yes, as the last slice*: it is small, and without it a person on a browser set to
   the wrong language has no way out. It can be split off if you prefer.
3. **Should the operator's mail follow the profile's `locale`?** It is the only signal there, but an
   operator may expect the deployment's default. *Recommendation: the profile*, falling back to the
   default; the Management API's description of `password-reset` says so.
4. **Which languages after French?** *Recommendation:* none in this issue; the catalogue test makes a
   contributed language complete or failing, and a `translations/README.md` says how to add one.
