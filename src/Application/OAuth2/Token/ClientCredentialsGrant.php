<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Token;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `grant_type=client_credentials` (RFC 6749 §4.4): a confidential client authenticating
 * as itself, for a token with **no subject**.
 *
 * There is no resource owner, no redirect and no browser, so none of the authorization
 * code machinery applies; the client secret is the whole credential. Two things are
 * left to get right:
 *
 * - **Only a client that can keep a secret.** `none` is not an accepted authentication
 *   method, so a public client — whose `client_id` anyone can read out of a binary —
 *   cannot get past client authentication at all. A client registered as public
 *   cannot hold a secret either: the registration refuses the combination.
 * - **No wider than granted.** A client holds no scope of its own. What it may take is
 *   its {@see \Clavia\Domain\ResourceServer\ClientGrant} on the API it names in
 *   `audience`, narrowed to what that API still defines. The `audience` is therefore
 *   required: a token for no API could carry nothing and open no door, since every
 *   resource server checks `aud` before `scope`.
 *
 * A scope beyond the grant is refused rather than quietly narrowed (RFC 6749 §3.3
 * permits either): nobody watches a machine's token response, and a silently weaker
 * token resurfaces much later as an unexplained 403. An omitted scope is the whole
 * grant — the server-defined default of §3.3 — because the grant itself is the
 * authorization decision; there is no person who could have consented to less.
 *
 * No refresh token (§4.4.3: a client that can authenticate once can simply do so again)
 * and no ID token (there is nobody for one to describe).
 */
final readonly class ClientCredentialsGrant implements Grant
{
    /**
     * @param positive-int $accessTokenLifetimeSeconds
     */
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private ClientGrantRepository $clientGrants,
        private AccessTokenRepository $tokens,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private int $accessTokenLifetimeSeconds,
    ) {
    }

    #[\Override]
    public function type(): GrantType
    {
        return GrantType::ClientCredentials;
    }

    #[\Override]
    public function acceptedAuthMethods(): array
    {
        return [ClientAuthMethod::ClientSecretBasic, ClientAuthMethod::ClientSecretPost];
    }

    #[\Override]
    public function issue(RequestParameters $parameters, Client $client): IssuedToken
    {
        $requested = $this->requestedScope($parameters);
        $audience = $this->audience($parameters);

        $resourceServer = $this->resourceServers->findByIdentifier($audience)
            ?? throw OAuth2Error::invalidTarget('No API is registered with this audience.');
        if ($resourceServer->isSystem && ! $client->isFirstParty()) {
            // Checked before the grant, so that even one written around `clients:grant` —
            // which refuses it — mints nothing.
            throw OAuth2Error::accessDenied('Third-party applications cannot access this API.');
        }

        $grant = $this->clientGrants->find($client->id, $resourceServer->id)
            ?? throw OAuth2Error::accessDenied('The client has not been granted access to this API.');
        $grantable = $grant->grantableOn($resourceServer);

        $scope = $requested ?? $grantable;
        $beyond = $scope->without($grantable);
        if (! $beyond->isEmpty()) {
            throw OAuth2Error::invalidScope(sprintf('The client may not request: %s.', $beyond->toString()));
        }

        $now = $this->clock->now();
        $value = $this->secrets->token();
        $token = AccessToken::issueToClient(
            AccessTokenId::generate($this->random),
            Digest::of($value),
            $client->id,
            $resourceServer->identifier,
            $scope,
            $now,
            $this->accessTokenLifetimeSeconds,
        );
        $this->tokens->add($token);

        return new IssuedToken($value, AccessToken::TOKEN_TYPE, $token->lifetimeFrom($now), $token->scope);
    }

    /**
     * The scope asked for; null when it was omitted.
     *
     * `openid` is refused outright, before anything else is looked at: it asks for an ID
     * token describing an end user, and this grant authenticates none — so not even an
     * API that mistakenly declares it, and a client granted it, can obtain one.
     *
     * @throws OAuth2Error
     */
    private function requestedScope(RequestParameters $parameters): ?ScopeSet
    {
        $value = $parameters->get('scope');
        if ($value === null) {
            return null;
        }

        try {
            $scope = ScopeSet::fromString($value);
        } catch (InvalidValue) {
            throw OAuth2Error::invalidScope('The requested scope is malformed.');
        }

        if ($scope->contains(OidcScope::OPENID)) {
            throw OAuth2Error::invalidScope(
                "The 'openid' scope asks for an ID token about an end user, and this grant authenticates none.",
            );
        }

        return $scope->isEmpty() ? null : $scope;
    }

    /**
     * @throws OAuth2Error
     */
    private function audience(RequestParameters $parameters): Audience
    {
        $value = $parameters->get('audience');
        if ($value === null) {
            throw OAuth2Error::invalidRequest("Missing 'audience' parameter: name the API the token is for.");
        }

        try {
            return Audience::fromString($value);
        } catch (InvalidValue) {
            throw OAuth2Error::invalidRequest("Invalid 'audience'.");
        }
    }
}
