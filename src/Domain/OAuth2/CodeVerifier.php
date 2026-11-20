<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * The PKCE secret a client keeps between its authorization request and its token
 * request (RFC 7636 §4.1).
 */
final readonly class CodeVerifier
{
    /** 43 to 128 characters of the unreserved set (RFC 7636 §4.1). */
    private const string PATTERN = '/^[A-Za-z0-9._~-]{43,128}$/D';

    /**
     * @param non-empty-string $value
     */
    private function __construct(#[\SensitiveParameter] public string $value)
    {
    }

    /**
     * @throws InvalidValue When the value is not a well-formed verifier.
     */
    public static function fromString(#[\SensitiveParameter] string $value): self
    {
        if ($value === '' || preg_match(self::PATTERN, $value) !== 1) {
            throw new InvalidValue(
                'A code verifier is 43 to 128 characters among A-Z, a-z, 0-9, "-", ".", "_" and "~".',
            );
        }

        return new self($value);
    }

    /** A fresh verifier with 64 bytes of entropy — what a client library would generate. */
    public static function generate(RandomSource $random): self
    {
        $value = rtrim(strtr(base64_encode($random->bytes(64)), '+/', '-_'), '=');
        assert($value !== '');

        return new self($value);
    }
}
