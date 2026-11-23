<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\DpopProofVerifier;
use Clavia\Domain\OAuth2\Dpop\DpopProof;

/**
 * A DPoP proof verifier that knows the proofs a test gave it, and nothing else: the cryptography
 * is the real adapter's ({@see \Clavia\Adapter\Secondary\Signing\Jose\JoseDpopProofVerifier}).
 */
final class FakeDpopProofVerifier implements DpopProofVerifier
{
    /** @var array<string, DpopProof> */
    private array $proofs = [];

    public function knows(string $compact, DpopProof $proof): void
    {
        $this->proofs[$compact] = $proof;
    }

    #[\Override]
    public function verify(string $proof): ?DpopProof
    {
        return $this->proofs[$proof] ?? null;
    }
}
