<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Dpop;

use Clavia\Application\Port\DpopNonces;
use Clavia\Application\Port\DpopProofVerifier;
use Clavia\Application\Port\DpopReplayCache;
use Clavia\Domain\OAuth2\Dpop\DpopProof;
use Clavia\Domain\OAuth2\Dpop\DpopRefusal;
use Clavia\Domain\OAuth2\Dpop\ProofRequirement;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Shared\Clock;

/**
 * The one door a DPoP proof comes in by (RFC 9449 §4.3; docs/design/dpop.md §5.1): exactly one
 * `DPoP` header; its cryptography ({@see DpopProofVerifier}); the request it is for
 * ({@see ProofRequirement}); the server's nonce where one is required (§8); and its `jti`, claimed
 * once per key (§11.1). In that order, so a proof that fails anything else never spends its `jti`.
 */
final readonly class ReadDpopProof
{
    /**
     * @param positive-int $lifetimeSeconds How old a proof may be (`CLAVIA_DPOP_PROOF_LIFETIME`).
     */
    public function __construct(
        private DpopProofVerifier $verifier,
        private DpopReplayCache $replays,
        private DpopNonces $nonces,
        private Clock $clock,
        private int $lifetimeSeconds,
    ) {
    }

    /**
     * @param list<string> $headers Every `DPoP` header the request carried.
     *
     * @return DpopProof|null Null when the request carried none.
     *
     * @throws OAuth2Error `invalid_dpop_proof`, or `use_dpop_nonce` with the nonce to use.
     */
    public function __invoke(array $headers, ProofRequirement $requirement, bool $nonceRequired): ?DpopProof
    {
        if ($headers === []) {
            return null;
        }
        // §4.3 step 1: one header, holding one proof.
        $proof = count($headers) === 1 ? $this->verifier->verify($headers[0]) : null;
        if ($proof === null) {
            throw OAuth2Error::invalidDpopProof(DpopRefusal::Malformed->value);
        }

        $refusal = $requirement->check($proof, $this->clock->now(), $this->lifetimeSeconds);
        if ($refusal !== null) {
            throw OAuth2Error::invalidDpopProof($refusal->value);
        }
        if ($nonceRequired && ($proof->nonce === null || ! $this->nonces->isCurrent($proof->nonce))) {
            throw OAuth2Error::useDpopNonce($this->nonces->current());
        }
        $remembered = $this->lifetimeSeconds + ProofRequirement::SKEW_SECONDS;
        if (! $this->replays->claim($proof->thumbprint, $proof->jti, $remembered)) {
            throw OAuth2Error::invalidDpopProof(DpopRefusal::Replayed->value);
        }

        return $proof;
    }

    /** The nonce a client should use next: sent with every answer to a request with a proof. */
    public function currentNonce(): string
    {
        return $this->nonces->current();
    }
}
