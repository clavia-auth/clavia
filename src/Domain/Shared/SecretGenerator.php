<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

/**
 * Mints the opaque secrets and identifiers the server hands out.
 *
 * Generated rather than chosen, always: a literal somebody typed invites exactly the
 * guessability and copy-paste collisions a random value does not.
 */
final readonly class SecretGenerator
{
    /** 32 bytes of entropy; base64url without padding makes 43 characters. */
    public const int TOKEN_ENTROPY_BYTES = 32;

    /**
     * Letters and digits only — no `-` or `_`. Used for identifiers that are public and
     * travel through URLs, logs and support tickets, where nothing should read as a
     * URL-safety artifact.
     */
    public const string ALPHANUMERIC = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

    /** Random characters after the underscore of a prefixed identifier. */
    public const int PREFIXED_ID_SUFFIX_LENGTH = 16;

    public function __construct(private RandomSource $random)
    {
    }

    /**
     * A fresh, high-entropy, URL-safe opaque token: an authorization code, an access or
     * refresh token, a session identifier, a client secret.
     *
     * @return non-empty-string 43 characters of the base64url alphabet (RFC 4648 §5).
     */
    public function token(): string
    {
        $encoded = rtrim(strtr(base64_encode($this->random->bytes(self::TOKEN_ENTROPY_BYTES)), '+/', '-_'), '=');
        assert($encoded !== '');

        return $encoded;
    }

    /**
     * @param positive-int $length
     *
     * @return non-empty-string `$length` letters and digits, each drawn uniformly.
     */
    public function alphanumeric(int $length): string
    {
        $last = strlen(self::ALPHANUMERIC) - 1;
        $value = '';
        for ($i = 0; $i < $length; $i++) {
            $value .= self::ALPHANUMERIC[$this->random->integer(0, $last)];
        }
        assert($value !== '');

        return $value;
    }

    /**
     * `<prefix>_` followed by 16 letters and digits — `rs_…`, `rol_…`.
     *
     * Stripe's convention: the prefix alone tells a reader — in a log line, a URL, a
     * support ticket — what kind of thing an identifier names, without a lookup.
     *
     * @param non-empty-string $prefix
     *
     * @return non-empty-string
     */
    public function prefixedId(string $prefix): string
    {
        return $prefix . '_' . $this->alphanumeric(self::PREFIXED_ID_SUFFIX_LENGTH);
    }
}
