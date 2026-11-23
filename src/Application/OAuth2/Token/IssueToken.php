<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Application\OAuth2\Dpop\ReadDpopProof;
use Clavia\Domain\OAuth2\Dpop\ProofRequirement;
use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\OAuth2Error;

/**
 * The token endpoint (RFC 6749 §3.2): authenticate the client, check it may use the
 * grant it asks for, and let that grant issue the token.
 *
 * A grant refused as `invalid_grant` — a wrong code or verifier, a replayed or unknown
 * refresh token, an unknown device code — counts as a failure ({@see ClientFailureThrottle}).
 * Answers a device is told to wait with (`authorization_pending`, `slow_down`) do not.
 *
 * A request carrying a DPoP proof (RFC 9449 §5) has it read before the grant runs — so a bad
 * proof never spends a code — with the server's nonce required (§8, docs/design/dpop.md §2), and
 * what the grant issues is bound to the proof's key. The answer then carries the next nonce.
 */
final readonly class IssueToken
{
    /** @var array<string, Grant> Keyed by `grant_type`. */
    private array $grants;

    /**
     * @param non-empty-string $tokenEndpoint The token endpoint's URL, as discovery names it: what a DPoP
     *                                        proof's `htu` must be (RFC 9449 §4.3).
     */
    public function __construct(
        private ClientAuthenticator $authenticator,
        private ClientFailureThrottle $throttle,
        private ReadDpopProof $dpop,
        private string $tokenEndpoint,
        Grant ...$grants,
    ) {
        $byType = [];
        foreach ($grants as $grant) {
            $byType[$grant->type()->value] = $grant;
        }
        $this->grants = $byType;
    }

    /**
     * @throws OAuth2Error
     * @throws TooManyFailedRequests
     */
    public function __invoke(TokenRequest $request): IssuedToken
    {
        $parameters = $request->parameters;

        $repeated = $parameters->repeated();
        if ($repeated !== []) {
            // RFC 6749 §3.2: "Request and response parameters MUST NOT be included more than once."
            throw OAuth2Error::invalidRequest(sprintf("Repeated '%s' parameter.", $repeated[0]));
        }

        $grantType = $parameters->get('grant_type');
        if ($grantType === null) {
            throw OAuth2Error::invalidRequest("Missing 'grant_type' parameter.");
        }

        $type = GrantType::tryFrom($grantType);
        $grant = $type === null ? null : ($this->grants[$type->value] ?? null);
        if ($type === null || $grant === null) {
            throw OAuth2Error::unsupportedGrantType('This server does not support the requested grant type.');
        }

        $client = $this->authenticator->authenticate($request->credentials(), $grant->acceptedAuthMethods());

        // Grants are opt-in per client: being able to authenticate is not being registered for a grant.
        if (! $client->mayUseGrant($type)) {
            throw OAuth2Error::unauthorizedClient(
                sprintf("The client is not authorized to use 'grant_type=%s'.", $type->value),
            );
        }

        $proof = ($this->dpop)($request->dpopProofs, new ProofRequirement('POST', $this->tokenEndpoint), true);

        try {
            $issued = $grant->issue($parameters, $client, $proof?->thumbprint);
        } catch (OAuth2Error $error) {
            if ($error->error === ErrorCode::InvalidGrant) {
                $this->throttle->recordRejectedGrant($request->clientAddress, $client);
            }

            throw $error;
        }

        return $proof === null ? $issued : $issued->withDpopNonce($this->dpop->currentNonce());
    }

    /**
     * The grant types this endpoint answers — what discovery advertises.
     *
     * @return list<GrantType>
     */
    public function supportedGrantTypes(): array
    {
        return array_map(static fn (Grant $grant): GrantType => $grant->type(), array_values($this->grants));
    }

    /**
     * Every client authentication method some grant accepts — what discovery advertises.
     *
     * @return list<ClientAuthMethod>
     */
    public function supportedAuthMethods(): array
    {
        $methods = [];
        foreach ($this->grants as $grant) {
            foreach ($grant->acceptedAuthMethods() as $method) {
                $methods[$method->value] = $method;
            }
        }

        return array_values($methods);
    }
}
