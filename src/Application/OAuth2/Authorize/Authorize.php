<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Authorize;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * The authorization endpoint (RFC 6749 §3.1, §4.1.1): validate the request, find out
 * who is granting it, and issue a single-use authorization code.
 *
 * The order of the checks is a security property:
 *
 * 1. **The client and its redirect URI, first, with no redirect on failure.** Until
 *    both are trusted there is nowhere safe to send an error; redirecting to an
 *    unregistered URI — even to report a problem — would make this endpoint an open
 *    redirector and hand codes to whoever supplied the URI.
 * 2. **Everything else about the request, reported to the client by redirect**
 *    (§4.1.2.1), `state` included.
 * 3. **Only then, the user.** Nobody is ever shown a login page for a request that
 *    would be refused anyway: an endpoint that asks for credentials on the strength of
 *    attacker-supplied parameters is a phishing surface.
 */
final readonly class Authorize
{
    /**
     * @param ScopeSet     $supportedScopes      What may be requested without naming an API: the OIDC scopes.
     * @param positive-int $codeLifetimeSeconds
     * @param positive-int $nonceLifetimeSeconds How long a used nonce is remembered: at least as long as a
     *                                           code carrying it, then an ID token minted from that code,
     *                                           remain valid.
     */
    public function __construct(
        private ClientRepository $clients,
        private AuthorizationCodeRepository $codes,
        private LoginStateStore $loginStates,
        private NonceRegistry $nonces,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private ScopeSet $supportedScopes,
        private int $codeLifetimeSeconds,
        private int $nonceLifetimeSeconds,
    ) {
    }

    /**
     * @throws OAuth2Error When the client or the redirect URI cannot be trusted. Answer locally;
     *                     never redirect.
     */
    public function __invoke(AuthorizationRequest $request): AuthorizationOutcome
    {
        $parameters = $request->parameters;

        $client = $this->client($parameters);
        $redirectUri = $this->redirectUri($parameters, $client);

        // `state` is only echoed when it is unambiguous.
        $state = $parameters->isRepeated('state') ? null : $parameters->get('state');

        try {
            $scope = $this->validate($parameters, $client);
            $challenge = $this->challenge($parameters);
            $nonce = $this->nonce($parameters, $client, $scope);
        } catch (OAuth2Error $refusal) {
            return new RequestRefused($redirectUri, $refusal, $state);
        }

        if ($request->endUser === null) {
            $handle = $this->secrets->token();
            $this->loginStates->put($handle, new LoginState($request->requestTarget, $client->id));

            return new LoginRequired($handle);
        }

        // Spent only now that a code is about to exist; atomic, so of two concurrent
        // requests carrying it only one gets a code.
        if ($nonce !== null && ! $this->nonces->claim($client->id, $nonce, $this->nonceLifetimeSeconds)) {
            return new RequestRefused($redirectUri, self::nonceReplayed(), $state);
        }

        $code = $this->secrets->token();
        $this->codes->add(AuthorizationCode::issue(
            AuthorizationCodeId::generate($this->random),
            Digest::of($code),
            $client->id,
            $request->endUser->userId,
            $redirectUri,
            $scope,
            $challenge,
            $nonce,
            $request->endUser->authentication(),
            $this->clock->now(),
            $this->codeLifetimeSeconds,
        ));

        return new CodeIssued($redirectUri, $code, $state);
    }

    /**
     * @throws OAuth2Error
     */
    private function client(RequestParameters $parameters): Client
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
    private function redirectUri(RequestParameters $parameters, Client $client): string
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
     * Everything that can be reported back to the client: repetition, the response
     * type, and the scope.
     *
     * @throws OAuth2Error
     */
    private function validate(RequestParameters $parameters, Client $client): ScopeSet
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

        try {
            $scope = ScopeSet::fromString($parameters->get('scope') ?? '');
        } catch (InvalidValue) {
            throw OAuth2Error::invalidScope('The requested scope is malformed.');
        }

        // An unknown scope fails outright rather than being dropped. RFC 6749 §3.3 allows
        // either; failing surfaces a client's misconfiguration instead of silently issuing
        // a token weaker than the one it asked for.
        $unknown = $scope->without($this->supportedScopes);
        if (! $unknown->isEmpty()) {
            throw OAuth2Error::invalidScope(sprintf('This server does not define: %s.', $unknown->toString()));
        }

        return $scope;
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
    private function nonce(RequestParameters $parameters, Client $client, ScopeSet $scope): ?Nonce
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

    private static function nonceReplayed(): OAuth2Error
    {
        return OAuth2Error::invalidRequest("The 'nonce' has already been used.");
    }

    /**
     * PKCE is mandatory for every client — confidential ones included — and `S256` is
     * the only method. A missing method is not defaulted: RFC 7636's default is
     * `plain`, the downgrade PKCE exists to prevent.
     *
     * @throws OAuth2Error
     */
    private function challenge(RequestParameters $parameters): CodeChallenge
    {
        $challenge = $parameters->get('code_challenge');
        if ($challenge === null) {
            throw OAuth2Error::invalidRequest("Missing 'code_challenge' parameter: PKCE is required.");
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
}
