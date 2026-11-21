<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Authorize;

use Clavia\Application\Authentication\EndUser;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\OAuth2\ReadRequestedAccess;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Consent\ConsentPolicy;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\Prompt;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Oidc\OidcScope;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
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
 *    attacker-supplied parameters is a phishing surface. A session established through
 *    a connection the application does not enable counts for nothing here: the person
 *    signs in again, through one it does.
 * 4. **Then their consent**, when {@see ConsentPolicy} says the request has to be put to
 *    them: the request goes on hold, and the browser to the consent screen.
 *
 * With `prompt=none` nothing may be shown: where step 3 or 4 would show a page, the
 * client is told `login_required` or `consent_required` instead (OIDC Core §3.1.2.6).
 */
final readonly class Authorize
{
    /**
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
        private ReadRequestedAccess $requestedAccess,
        private RoleRepository $roles,
        private ConsentRepository $consents,
        private ConsentStateStore $consentStates,
        private ConnectionAccess $connections,
        private Sessions $sessions,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
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
            [$scope, $target] = $this->validate($parameters, $client);
            $challenge = $this->challenge($parameters);
            $nonce = $this->nonce($parameters, $client, $scope);
            $prompt = Prompt::fromParameter($parameters->get('prompt'));
        } catch (OAuth2Error $refusal) {
            return new RequestRefused($redirectUri, $refusal, $state);
        }

        $endUser = $request->endUser;
        $session = $endUser?->session;
        if ($session !== null && ! $this->connections->allows($client, $session->connection)) {
            $endUser = null;
        }
        if ($endUser === null) {
            if ($prompt->forbidsInteraction()) {
                return new RequestRefused(
                    $redirectUri,
                    OAuth2Error::loginRequired("Nobody is signed in, and 'prompt=none' forbids asking."),
                    $state,
                );
            }

            $handle = $this->secrets->token();
            $this->loginStates->put($handle, new LoginState($request->resumption($parameters), $client->id));

            return new LoginRequired($handle);
        }

        // On an API that enforces roles, somebody holding nothing there is refused now —
        // the first point where both the API and the person are known — rather than given
        // a code for a token that would fail every call with nothing to say why. What they
        // do hold is applied at redemption, where roles are read again.
        if (
            $target !== null
            && $target->enforcePolicies
            && $this->roles->permissionsHeld($endUser->userId, $target->id)->isEmpty()
        ) {
            return new RequestRefused(
                $redirectUri,
                OAuth2Error::accessDenied('Your account holds no permission on this API.'),
                $state,
            );
        }

        $given = $this->consents->find($endUser->userId, $client->id, $target?->id);
        if (ConsentPolicy::mustAsk($client, $target, $prompt, $scope, $given)) {
            if ($prompt->forbidsInteraction()) {
                return new RequestRefused(
                    $redirectUri,
                    OAuth2Error::consentRequired("The request needs consent, and 'prompt=none' forbids asking."),
                    $state,
                );
            }

            return $this->holdForConsent($request, $endUser, $client, $redirectUri, $state, $scope, $target, $prompt);
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
            $endUser->userId,
            $redirectUri,
            $scope,
            $challenge,
            $target?->identifier,
            $nonce,
            $endUser->authentication(),
            $this->clock->now(),
            $this->codeLifetimeSeconds,
        ));
        // With a code in hand the application is about to hold a session of its own on the
        // strength of this one; when this one ends, it is told (Back-Channel Logout 1.0).
        if ($endUser->session !== null) {
            $this->sessions->recordClient($endUser->session, $client->id);
        }

        return new CodeIssued($redirectUri, $code, $state);
    }

    /**
     * Put the request on hold behind a fresh handle, for the consent screen to show and
     * decide. Allowing sends the browser back to the request — without the `consent` it
     * may have prompted for, which has then been given, or it would ask forever.
     */
    private function holdForConsent(
        AuthorizationRequest $request,
        EndUser $endUser,
        Client $client,
        string $redirectUri,
        ?string $state,
        ScopeSet $scope,
        ?ResourceServer $target,
        Prompt $prompt,
    ): ConsentRequired {
        $handle = $this->secrets->token();
        $this->consentStates->park($handle, new PendingConsent(
            $request->resumption($request->parameters->with('prompt', $prompt->without(Prompt::CONSENT))),
            $redirectUri,
            $state,
            $endUser->userId,
            $client->id,
            $scope,
            $target?->id,
        ));

        return new ConsentRequired($handle);
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
     * type, the audience — which a third-party application may not set to a system API —
     * and the scope.
     *
     * @return array{ScopeSet, ResourceServer|null} The scope, and the API it was checked against.
     *
     * @throws OAuth2Error
     */
    private function validate(RequestParameters $parameters, Client $client): array
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
