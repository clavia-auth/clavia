# Translations

What a person reads on `auth.{domain}`, in each language this server offers: one
[ARB](https://github.com/google/app-resource-bundle) file per language, `en.arb` the source.
The design is `docs/design/translated-sign-in-pages.md`.

## The files

- `en.arb`, the source: `@@locale`, then every message as `"key": "message"`, and beside a message
  that needs it a `"@key"` entry, with a `description` for translators and, for a message with
  arguments, its `placeholders`, each with an `example`.
- Every other file holds `@@locale` and the same messages, translated, and nothing else: the
  descriptions are the source's.

Messages are [ICU MessageFormat](https://unicode-org.github.io/icu/userguide/format_parse/messages/):

```json
"login.continue_with": "Continue with {provider}",
"mail.reset.expires": "It expires in {minutes, plural, one {# minute} other {# minutes}}."
```

- `{provider}` is a value the server puts in; keep its name as it is, and move it where the
  sentence needs it.
- A plural gives the forms the language has (`one`, `other`; some languages have `few` or `many`
  too). French counts 0 as singular, which ICU knows.
- A message is text: no HTML, no entities. Emphasis is the page's business.
- An apostrophe followed by `{`, `}` or `#` starts quoted text in ICU. Write `l'{provider}` as
  `l''{provider}`, or rephrase.

## Adding a language

1. Copy `en.arb` to `<tag>.arb` (a BCP 47 tag: `de`, `pt-BR`), set `@@locale`, delete every
   `@` entry but `@@locale`, and translate each message.
2. Add the tag to `CLAVIA_LANGUAGES` where it should be offered.
3. Run `make test`: `CatalogueTest` says what is missing, extra, unparsable or has different
   arguments from the source.

A deployment offering a language without a file here refuses to start.

## Adding a message

Add it to `en.arb` (with a description if its wording or its arguments need context, and
placeholders if it has arguments) and to every other file, then use it: `$this->t('key')` in a
template, `Message::of('key')` in a page class. `CatalogueTest` fails on a key used but missing,
and on one present but used nowhere.
