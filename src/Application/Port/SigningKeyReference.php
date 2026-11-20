<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Oidc\SigningAlgorithm;

/**
 * Names a signing key without holding it: what goes in a JWS header (`kid`, `alg`) and
 * what {@see TokenSigner::sign()} is asked to sign with.
 *
 * The `kid` is deliberately not a provider's full key reference — an AWS ARN carries the
 * account number, a GCP resource name the project — because it is published to every
 * relying party.
 */
final readonly class SigningKeyReference
{
    /**
     * @param non-empty-string $kid
     */
    public function __construct(
        public string $kid,
        public SigningAlgorithm $algorithm,
    ) {
    }
}
