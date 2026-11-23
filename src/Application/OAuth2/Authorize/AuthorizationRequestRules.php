<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Authorize;

use Clavia\Application\OAuth2\ReadRequestedAccess;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Authentication\AuthenticationRequirement;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;

/**
 * The rules an authorization request must keep, whichever way it arrives: at the authorization
 * endpoint, or pushed first to `/oauth2/par` (RFC 9126 §2.1, which asks the pushed request to be
 * validated as the authorization endpoint would). One place, so the two cannot drift.
 *
 * Each rule throws the {@see OAuth2Error} the specification answers with; what to do with it —
 * a redirect to the client, a page, a JSON document — is the caller's.
 */
final readonly class AuthorizationRequestRules
{
    public function __construct(
        private ClientRepository $clients,
        private NonceRegistry $nonces,
        private ReadRequestedAccess $requestedAccess,
    ) {
    }

    /**
     * @throws OAuth2Error
     */
    public function client(RequestParameters $parameters): Client
    {
        $clientId = $parameters->get('client_id');
        if ($clientId === null || $parameters->isRepeated('client_id')) {
            throw OAuth2Error::invalidClient("Missing or repeated 'client_id' parameter.");
        }

        try {
            $client = $this->clients->find(ClientId::fromString($clientId));
        } catch (InvalidValue) {
            $client = null;
        }

        return $client ?? throw OAuth2Error::invalidClient('The client does not exist on this server.');
    }

    /**
     * The redirect URI the response will be sent to, checked by exact match against the
     * client's registration (OAuth 2.1 §2.3.1).
     *
     * @throws OAuth2Error
     */
    public function redirectUri(RequestParameters $parameters, Client $client): string
    {
        if ($parameters->isRepeated('redirect_uri')) {
            throw OAuth2Error::invalidRequest("Repeated 'redirect_uri' parameter.");
        }

        $redirectUri = $parameters->get('redirect_uri');
        if ($redirectUri === null) {
            // RFC 6749 §3.1.2.3: it may be omitted only when exactly one is registered.
            $sole = $client->soleRedirectUri();
            if ($sole === null) {
                throw OAuth2Error::invalidRequest("Missing 'redirect_uri' parameter.");
            }

            return $sole->value;
        }

        if (! $client->hasRedirectUri($redirectUri)) {
            throw OAuth2Error::invalidRequest('The redirect URI is not registered for this client.');
        }

        return $redirectUri;
    }

    /**
     * OIDC Core §6: this server takes no request object, by value or by reference, and
     * says so with the errors defined for that.
     *
     * @throws OAuth2Error
     */
    public static function refuseRequestObjects(RequestParameters $parameters): void
    {
        if ($parameters->get('request') !== null) {
            throw OAuth2Error::requestNotSupported('Request objects are not supported: send the parameters as such.');
        }
        if ($parameters->get('request_uri') !== null) {
            throw OAuth2Error::requestUriNotSupported('Request objects by reference are not supported.');
        }
    }

    /**
     * Everything that can be reported back to the client: repetition, the response
     * type, the audience — which a third-party application may not set to a system API —
     * and the scope.
     *
     * @return array{ScopeSet, ResourceServer|null} The scope, and the API it was checked against.
     *
     * @throws OAuth2Error
     */
    public function validate(RequestParameters $parameters, Client $client): array
    {
        $repeated = $parameters->repeated();
        if ($repeated !== []) {
            // RFC 6749 §3.1: "Request and response parameters MUST NOT be included more than once."
            throw OAuth2Error::invalidRequest(sprintf("Repeated '%s' parameter.", $repeated[0]));
        }

        $responseType = $parameters->get('response_type');
        if ($responseType === null) {
            throw OAuth2Error::invalidRequest("Missing 'response_type' parameter.");
        }

        $type = ResponseType::tryFrom($responseType);
        if ($type === null) {
            throw OAuth2Error::unsupportedResponseType(
                'This server only supports response_type=code.',
            );
        }
        if (! $client->mayUseResponseType($type)) {
            throw OAuth2Error::unauthorizedClient(
                sprintf("The client is not authorized to use 'response_type=%s'.", $type->value),
            );
        }

        $access = ($this->requestedAccess)($parameters, $client);

        return [$access->scope, $access->target];
    }

    /**
     * The `nonce` of an OpenID Connect request (OIDC Core §3.1.2.1), refused when this
     * client has used it before: a captured authorization URL must not be answered twice.
     *
     * Only an OpenID Connect request — one asking for `openid` — has a nonce. Anywhere
     * else the parameter means nothing, and an unknown parameter is ignored (RFC 6749
     * §3.1). Optional in the code flow, so its absence is not an error.
     *
     * @throws OAuth2Error
     */
    public function nonce(RequestParameters $parameters, Client $client, ScopeSet $scope): ?Nonce
    {
        $value = $parameters->get('nonce');
        if ($value === null || ! $scope->contains(OidcScope::OPENID)) {
            return null;
        }

        try {
            $nonce = Nonce::fromString($value);
        } catch (InvalidValue) {
            throw OAuth2Error::invalidRequest("Invalid 'nonce'.");
        }

        if ($this->nonces->isUsed($client->id, $nonce)) {
            throw self::nonceReplayed();
        }

        return $nonce;
    }

    public static function nonceReplayed(): OAuth2Error
    {
        return OAuth2Error::invalidRequest("The 'nonce' has already been used.");
    }

    /**
     * PKCE is mandatory for every client — confidential ones included — and `S256` is
     * the only method. A missing method is not defaulted: RFC 7636's default is
     * `plain`, the downgrade PKCE exists to prevent.
     *
     * The one exception is OAuth 2.1 §7.5.1's: a confidential client the operator relieved
     * of PKCE may omit it from an OpenID Connect request that carries a `nonce`, which
     * then binds the code to the client's own request instead — the ID token repeats it.
     * A challenge it does send is checked like any other.
     *
     * @throws OAuth2Error
     */
    public static function challenge(RequestParameters $parameters, Client $client, ?Nonce $nonce): ?CodeChallenge
    {
        $challenge = $parameters->get('code_challenge');
        if ($challenge === null && ! $client->requiresPkce && $nonce !== null) {
            return null;
        }
        if ($challenge === null) {
            throw OAuth2Error::invalidRequest($client->requiresPkce
                ? "Missing 'code_challenge' parameter: PKCE is required."
                : "Missing 'code_challenge' parameter: PKCE is required unless an OpenID Connect request carries "
                    . "a 'nonce'.");
        }

        $method = $parameters->get('code_challenge_method');
        if ($method === null) {
            throw OAuth2Error::invalidRequest("Missing 'code_challenge_method' parameter.");
        }
        if ($method !== CodeChallenge::METHOD) {
            throw OAuth2Error::invalidRequest("Unsupported 'code_challenge_method': only S256 is accepted.");
        }

        try {
            return CodeChallenge::fromString($challenge);
        } catch (InvalidValue) {
            throw OAuth2Error::invalidRequest("Invalid 'code_challenge'.");
        }
    }

    /**
     * What the request asks of the sign-in: `acr_values`, of which only the levels this server
     * knows count (docs/design/mfa-policies.md §2).
     *
     * @throws OAuth2Error
     */
    public static function requirement(RequestParameters $parameters): AuthenticationRequirement
    {
        try {
            return AuthenticationRequirement::fromAcrValues($parameters->get('acr_values'));
        } catch (InvalidValue) {
            throw OAuth2Error::invalidRequest("'acr_values' must name at least one value.");
        }
    }

    /**
     * `dpop_jkt` (RFC 9449 §10): the thumbprint of the DPoP key that will redeem the code, so a code
     * stolen on its way back cannot be redeemed with anyone else's key. Optional.
     *
     * @throws OAuth2Error
     */
    public static function dpopKey(RequestParameters $parameters): ?JwkThumbprint
    {
        $value = $parameters->get('dpop_jkt');
        if ($value === null) {
            return null;
        }

        try {
            return JwkThumbprint::fromString($value);
        } catch (InvalidValue) {
            throw OAuth2Error::invalidRequest("'dpop_jkt' must be a JWK SHA-256 thumbprint.");
        }
    }
}
