<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Shared\InvalidValue;

/**
 * The signature algorithms Clavia offers when a passkey is made, as COSE algorithm
 * identifiers (RFC 9053 §2.2, §2.1 and RFC 8812 §2), in order of preference.
 *
 * What platform authenticators and security keys produce; RS256 is there for Windows Hello.
 */
enum CoseAlgorithm: int
{
    /** EdDSA over Ed25519. */
    case EdDSA = -8;

    /** ECDSA over P-256 with SHA-256. */
    case ES256 = -7;

    /** RSASSA-PKCS1-v1_5 with SHA-256. */
    case RS256 = -257;

    /**
     * The algorithms to offer, most preferred first.
     *
     * @return list<self>
     */
    public static function preferred(): array
    {
        return [self::EdDSA, self::ES256, self::RS256];
    }

    /** @throws InvalidValue When Clavia does not offer it. */
    public static function fromIdentifier(int $identifier): self
    {
        return self::tryFrom($identifier) ?? throw new InvalidValue('That signature algorithm is not offered.');
    }
}
