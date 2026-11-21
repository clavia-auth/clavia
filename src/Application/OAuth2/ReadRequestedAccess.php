<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2;

use Clavia\Domain\Client\Client;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Reads `scope` and `audience` from a request for a person's tokens — the authorization
 * endpoint's and the device authorization endpoint's alike, so the two cannot disagree
 * about what may be asked for.
 */
final readonly class ReadRequestedAccess
{
    /**
     * @param ScopeSet $supportedScopes What may be requested without naming an API: the OIDC scopes.
     */
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private ScopeSet $supportedScopes,
    ) {
    }

    /**
     * @throws OAuth2Error `invalid_request` for a malformed audience, `invalid_target` for an unknown
     *                     one, `access_denied` for a third-party application naming a system API,
     *                     `invalid_scope` for a malformed scope or one nothing defines.
     */
    public function __invoke(RequestParameters $parameters, Client $client): RequestedAccess
    {
        $target = $this->target($parameters);
        if ($target !== null && $target->isSystem && ! $client->isFirstParty()) {
            // The server's own API — its users, its applications, its roles — is for the
            // operator's applications only: an outsider's application gets no token for it
            // on anybody's behalf, whatever the person would agree to.
            throw OAuth2Error::accessDenied('Third-party applications cannot access this API.');
        }

        try {
            $scope = ScopeSet::fromString($parameters->get('scope') ?? '');
        } catch (InvalidValue) {
            throw OAuth2Error::invalidScope('The requested scope is malformed.');
        }

        // An unknown scope fails outright rather than being dropped. RFC 6749 §3.3 allows
        // either; failing surfaces a client's misconfiguration instead of silently issuing
        // a token weaker than the one it asked for. What is known: the OIDC scopes, and the
        // permissions of the API named in `audience`.
        $known = $target === null
            ? $this->supportedScopes
            : $this->supportedScopes->union($target->permissionScopes());
        $unknown = $scope->without($known);
        if (! $unknown->isEmpty()) {
            throw OAuth2Error::invalidScope(sprintf(
                '%s does not define: %s.',
                $target === null ? 'This server' : sprintf("The API '%s'", $target->identifier->value),
                $unknown->toString(),
            ));
        }

        return new RequestedAccess($scope, $target);
    }

    /**
     * The API named in `audience`, whose permissions may then be asked for; null when the
     * request names none and asks for the OIDC scopes alone.
     *
     * `audience` rather than RFC 8707's `resource`: single-valued, as the hosted providers
     * spell it, and the value the token's `aud` becomes. An unknown one is RFC 8707's
     * `invalid_target` nonetheless — the same failure, and a registered code for it.
     *
     * @throws OAuth2Error
     */
    private function target(RequestParameters $parameters): ?ResourceServer
    {
        $value = $parameters->get('audience');
        if ($value === null) {
            return null;
        }

        try {
            $audience = Audience::fromString($value);
        } catch (InvalidValue) {
            throw OAuth2Error::invalidRequest("Invalid 'audience'.");
        }

        return $this->resourceServers->findByIdentifier($audience)
            ?? throw OAuth2Error::invalidTarget('No API is registered with this audience.');
    }
}
