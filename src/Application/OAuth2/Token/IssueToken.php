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
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\OAuth2Error;

/**
 * The token endpoint (RFC 6749 §3.2): authenticate the client, check it may use the
 * grant it asks for, and let that grant issue the token.
 */
final readonly class IssueToken
{
    /** @var array<string, Grant> Keyed by `grant_type`. */
    private array $grants;

    public function __construct(
        private ClientAuthenticator $authenticator,
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

        return $grant->issue($parameters, $client);
    }
}
