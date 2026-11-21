<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

/**
 * The `prompt` of an authorization request (OpenID Connect Core §3.1.2.1): what the
 * client wants this server to show, or not show, to the person.
 *
 * A space-separated list of case-sensitive values. Two are acted on:
 *
 * - `consent` — ask for consent even when it was given before or would not be needed.
 * - `none` — show nothing at all. When somebody would have to sign in, the answer is
 *   `login_required`; when they would have to consent, `consent_required` (§3.1.2.6).
 *   Asking for nothing *and* something is a contradiction: `none` with any other value is
 *   `invalid_request`.
 *
 * `login` and `select_account` are not acted on yet (see `docs/DEVIATIONS.md`), and are
 * not advertised in discovery; a value this server does not know is ignored.
 */
final readonly class Prompt
{
    public const string NONE = 'none';

    public const string CONSENT = 'consent';

    /**
     * @param list<non-empty-string> $values Each once, in the order given.
     */
    private function __construct(private array $values)
    {
    }

    /**
     * @param string|null $parameter The parameter as received; null when absent.
     *
     * @throws OAuth2Error When `none` is combined with another value.
     */
    public static function fromParameter(?string $parameter): self
    {
        $values = [];
        foreach (explode(' ', $parameter ?? '') as $value) {
            if ($value !== '' && ! in_array($value, $values, true)) {
                $values[] = $value;
            }
        }
        if (in_array(self::NONE, $values, true) && count($values) > 1) {
            throw OAuth2Error::invalidRequest("'prompt=none' cannot be combined with another value.");
        }

        return new self($values);
    }

    /** Whether nothing may be shown: any interaction needed is an error for the client. */
    public function forbidsInteraction(): bool
    {
        return in_array(self::NONE, $this->values, true);
    }

    /** Whether the client asked for the consent screen whatever was agreed before. */
    public function demandsConsent(): bool
    {
        return in_array(self::CONSENT, $this->values, true);
    }

    /**
     * The parameter without `$value` — for the request a page sends the browser back to,
     * once what that value asked for has happened: a request that still said
     * `prompt=consent` after consent was given would ask again, forever. Null when nothing
     * is left.
     */
    public function without(string $value): ?string
    {
        $rest = array_values(array_filter($this->values, static fn (string $kept): bool => $kept !== $value));

        return $rest === [] ? null : implode(' ', $rest);
    }
}
