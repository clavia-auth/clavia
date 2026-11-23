<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2\Dpop;

use Clavia\Domain\Shared\InvalidValue;

/**
 * The RFC 7638 SHA-256 thumbprint of a public key, base64url without padding: how a token names
 * the key it is bound to (`cnf.jkt`, RFC 9449 §6.1), and how the authorization endpoint is told
 * which key will redeem a code (`dpop_jkt`, §10).
 */
final readonly class JwkThumbprint
{
    private function __construct(public string $value)
    {
    }

    /**
     * @throws InvalidValue When it is not 43 base64url characters: the length of a SHA-256 digest.
     */
    public static function fromString(string $value): self
    {
        if (preg_match('/^[A-Za-z0-9_-]{43}$/D', $value) !== 1) {
            throw new InvalidValue('A JWK thumbprint is a base64url SHA-256 digest: 43 characters.');
        }

        return new self($value);
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->value, $other->value);
    }
}
