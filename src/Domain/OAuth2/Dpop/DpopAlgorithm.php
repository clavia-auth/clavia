<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2\Dpop;

/**
 * The algorithms a DPoP proof may be signed with (docs/design/dpop.md §2): asymmetric only
 * (RFC 9449 §4.2), and what WebCrypto, platform keystores and the common libraries make. What
 * discovery advertises (`dpop_signing_alg_values_supported`) and what the verifier accepts.
 *
 * No PS256: the verification library implements RSA-PSS in pure PHP, at about a second of CPU
 * per proof, and a proof's signature is checked before anything else, so anyone could make the
 * token endpoint burn a second per request with forged proofs. RS256 covers RSA keys.
 */
enum DpopAlgorithm: string
{
    case ES256 = 'ES256';
    case EdDSA = 'EdDSA';
    case RS256 = 'RS256';

    /** @return list<string> */
    public static function supported(): array
    {
        return array_map(static fn (self $algorithm): string => $algorithm->value, self::cases());
    }
}
