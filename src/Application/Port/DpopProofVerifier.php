<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\OAuth2\Dpop\DpopProof;

/**
 * Checks the cryptography of a DPoP proof (RFC 9449 §4.3 steps 2–8), and only that.
 *
 * A JWS in compact form whose header has `typ: dpop+jwt`, an `alg` of
 * {@see \Clavia\Domain\OAuth2\Dpop\DpopAlgorithm}, and a `jwk` that is a public key of the
 * algorithm's type with no private member; signed by that key; carrying `jti`, `htm`, `htu`
 * and `iat`. Whether it is for the request at hand is
 * {@see \Clavia\Domain\OAuth2\Dpop\ProofRequirement}'s.
 */
interface DpopProofVerifier
{
    /** The proof's claims and key thumbprint; null for anything that is not such a proof. */
    #[\NoDiscard]
    public function verify(string $proof): ?DpopProof;
}
