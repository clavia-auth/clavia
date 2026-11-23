<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\ProtectedResource;

use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\OAuth2\Dpop\DpopRefusal;
use Clavia\Domain\OAuth2\Dpop\ProofRequirement;
use Clavia\Domain\OAuth2\OAuth2Error;

/**
 * Whether a token was presented the way it must be, at this server's own protected resources —
 * userinfo and the Management API (RFC 9449 §7; docs/design/dpop.md §5.4):
 *
 * - a token bound to a DPoP key needs the `DPoP` scheme and a fresh proof from that key, for this
 *   method and URL, naming this token (`ath`). Presented as `Bearer`, it is `invalid_token`
 *   (§7.2): otherwise binding would be optional for whoever stole it;
 * - a bearer token presented with the `DPoP` scheme is `invalid_token` too: there is no key to
 *   check the proof against.
 *
 * No server nonce here (design question 2): the proof's age and the `jti` cache bound replay.
 */
final readonly class CheckSenderConstraint
{
    public function __construct(private ReadDpopProof $dpop)
    {
    }

    /**
     * @param non-empty-string $method
     * @param non-empty-string $url    The resource's URL as this server knows it: a proof's `htu`.
     *
     * @throws BearerTokenError `invalid_token`, or `invalid_dpop_proof`.
     */
    public function __invoke(
        AccessToken $token,
        PresentedCredentials $credentials,
        string $method,
        string $url,
    ): void {
        $bound = $token->dpopJkt;
        if ($credentials->scheme === TokenScheme::Bearer) {
            if ($bound !== null) {
                throw BearerTokenError::invalidToken('The access token is bound to a key: present it with DPoP.');
            }

            return;
        }
        if ($bound === null) {
            throw BearerTokenError::invalidToken('The access token is not bound to a key.');
        }

        try {
            $proof = ($this->dpop)(
                $credentials->dpopProofs,
                new ProofRequirement($method, $url, $credentials->accessToken, $bound),
                false,
            );
        } catch (OAuth2Error $refusal) {
            throw BearerTokenError::invalidDpopProof($refusal->reason ?? 'refused');
        }
        if ($proof === null) {
            throw BearerTokenError::invalidDpopProof(DpopRefusal::Missing->value);
        }
    }
}
