<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Keys;

use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Oidc\PublicJwk;

/**
 * The public keys relying parties verify this server's tokens with: the JWK Set
 * (RFC 7517 §5) published at the `jwks_uri`.
 */
final readonly class PublishSigningKeys
{
    /**
     * How long a relying party may cache the set, in seconds.
     *
     * A rotation-safety number, not an HTTP detail: it bounds how far a cached copy can
     * lag behind — still missing a key that just started signing, or still trusting one
     * just withdrawn. The rotation grace covers the second case many times over; the
     * first is why a rotation publishes the new key the moment it signs, so a relying
     * party that refetches on an unknown `kid` finds it.
     */
    public const int CACHE_MAX_AGE = 3600;

    public function __construct(private TokenSigner $signer)
    {
    }

    /** @return list<PublicJwk> */
    public function __invoke(): array
    {
        return $this->signer->publicKeys();
    }
}
