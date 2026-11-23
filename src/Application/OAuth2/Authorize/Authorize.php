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
use Clavia\Application\Authentication\Mfa\BeginEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\BeginStepUp;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\NonceRegistry;
use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Domain\Authentication\AuthenticationRequirement;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Consent\ConsentPolicy;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\OAuth2\MaxAge;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\Prompt;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
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
 *    (§4.1.2.1), `state` included. A request object — `request` or `request_uri` — is
 *    refused first (OIDC Core §6.1, §6.2): honouring the plain parameters of a request
 *    whose signed half may say something else would be worse than refusing it.
 * 3. **Only then, the user.** Nobody is ever shown a login page for a request that
 *    would be refused anyway: an endpoint that asks for credentials on the strength of
 *    attacker-supplied parameters is a phishing surface. A session established through
 *    a connection the application does not enable counts for nothing here: the person
 *    signs in again, through one it does. So does somebody the client asked to see
 *    again: `prompt=login` or `select_account`, or a sign-in older than `max_age`.
 *    A person signed in less strongly than `acr_values`, or the application's or the API's
 *    MFA policy, asks (docs/design/mfa-policies.md §5.1) steps up: one more factor on the
 *    second-factor page, and the request is decided again. Someone with no second factor
 *    at all, asked for MFA, sets one up on the way if their address is verified (§5.3);
 *    anyone else is refused with `unmet_authentication_requirements`.
 * 4. **Then their consent**, when {@see ConsentPolicy} says the request has to be put to
 *    them: the request goes on hold, and the browser to the consent screen.
 *
 * With `prompt=none` nothing may be shown: where step 3 or 4 would show a page, the
 * client is told `login_required`, `interaction_required` (a step-up) or `consent_required`
 * instead (OIDC Core §3.1.2.6).
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
        private AuthorizationRequestRules $rules,
        private AuthorizationCodeRepository $codes,
        private LoginStateStore $loginStates,
        private NonceRegistry $nonces,
        private RoleRepository $roles,
        private ConsentRepository $consents,
        private ConsentStateStore $consentStates,
        private ConnectionAccess $connections,
        private Sessions $sessions,
        private PushedAuthorizationRequestStore $pushedRequests,
        private BeginStepUp $beginStepUp,
        private BeginEnrolmentOnTheWay $beginEnrolment,
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
        [$request, $pushed] = $this->readByReference($request);
        $parameters = $request->parameters;

        $client = $this->rules->client($parameters);
        $redirectUri = $this->rules->redirectUri($parameters, $client);

        // `state` is only echoed when it is unambiguous.
        $state = $parameters->isRepeated('state') ? null : $parameters->get('state');

        try {
            if ($client->requiresPushedAuthorizationRequests && $pushed === null) {
                // RFC 9126 §6: this client's requests come pushed, or not at all.
                throw OAuth2Error::invalidRequest('This client must push its authorization requests to /oauth2/par.');
            }
            AuthorizationRequestRules::refuseRequestObjects($parameters);
            [$scope, $target] = $this->rules->validate($parameters, $client);
            $nonce = $this->rules->nonce($parameters, $client, $scope);
            $challenge = AuthorizationRequestRules::challenge($parameters, $client, $nonce);
            $prompt = Prompt::fromParameter($parameters->get('prompt'));
            $maxAge = MaxAge::fromParameter($parameters->get('max_age'));
            $requirement = AuthorizationRequestRules::requirement($parameters);
        } catch (OAuth2Error $refusal) {
            return new RequestRefused($redirectUri, $refusal, $state);
        }
        // The application's and the API's MFA policies put a floor under `acr_values`.
        $requirement = $requirement
            ->withMinimum($client->mfaPolicy->level())
            ->withMinimum($target?->mfaPolicy->level());

        $endUser = $request->endUser;
        $session = $endUser?->session;
        if ($session !== null && ! $this->connections->allows($client, $session->connection)) {
            $endUser = null;
        }
        if ($endUser !== null && $this->mustBeSeenAgain($endUser, $prompt, $maxAge)) {
            $endUser = null;
        }
        if ($endUser === null) {
            if ($prompt->forbidsInteraction()) {
                return new RequestRefused(
                    $redirectUri,
                    OAuth2Error::loginRequired("The person must sign in, and 'prompt=none' forbids asking."),
                    $state,
                );
            }

            // The sign-in about to happen satisfies `login`, `select_account` and
            // `max_age=0`; the request the browser returns to must not ask for them again,
            // or it would ask forever. Every other value stays.
            $resumed = $parameters->with('prompt', $prompt->without(Prompt::LOGIN, Prompt::SELECT_ACCOUNT));
            if ($maxAge?->isZero() === true) {
                $resumed = $resumed->with('max_age', null);
            }
            $handle = $this->secrets->token();
            $returnTo = $this->resume($request, $resumed, $client, $pushed);
            $this->loginStates->put($handle, new LoginState($returnTo, $client->id));

            return new LoginRequired($handle);
        }

        if (! $requirement->isMetBy($endUser->session?->methods ?? [])) {
            return $this->stepUp($request, $endUser, $client, $redirectUri, $state, $requirement, $prompt, $pushed);
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

            return $this->holdForConsent(
                $request,
                $endUser,
                $client,
                $redirectUri,
                $state,
                $scope,
                $target,
                $prompt,
                $pushed,
            );
        }

        // A pushed request yields one code (RFC 9126 §4); spent now, atomically, like the nonce.
        if ($pushed !== null && ! $this->pushedRequests->spend($pushed)) {
            return new RequestRefused(
                $redirectUri,
                OAuth2Error::invalidRequest("The 'request_uri' has already been used."),
                $state,
            );
        }

        // Spent only now that a code is about to exist; atomic, so of two concurrent
        // requests carrying it only one gets a code.
        if ($nonce !== null && ! $this->nonces->claim($client->id, $nonce, $this->nonceLifetimeSeconds)) {
            return new RequestRefused($redirectUri, AuthorizationRequestRules::nonceReplayed(), $state);
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
     * A request by reference (RFC 9126 §4): the parameters it pushed replace the query, which
     * carries only `client_id` — required, and the pushing client's — and `request_uri`. Anything
     * else in the query is ignored, as RFC 9101 §5 has the parameters of a request object win.
     * A `request_uri` this server did not hand out is left for the rules to refuse
     * (`request_uri_not_supported`).
     *
     * @return array{AuthorizationRequest, string|null} The request to decide, and the pushed request's
     *                                                 handle when there is one.
     *
     * @throws OAuth2Error When the `request_uri` is unknown, expired or another client's: there is
     *                     then no redirect URI to trust, so it is shown, never redirected.
     */
    private function readByReference(AuthorizationRequest $request): array
    {
        $query = $request->parameters;
        $requestUri = $query->get('request_uri');
        $handle = $requestUri === null || $query->isRepeated('request_uri')
            ? null
            : PushedAuthorizationRequest::handleOf($requestUri);
        if ($handle === null || $handle === '') {
            return [$request, null];
        }

        $client = $this->rules->client($query);
        $pushed = $this->pushedRequests->find($handle);
        if ($pushed === null || ! $pushed->clientId->equals($client->id)) {
            throw OAuth2Error::invalidRequest("The 'request_uri' is unknown, has expired, or is another client's.");
        }

        return [$request->withParameters(RequestParameters::fromPairs($pushed->parameters)), $handle];
    }

    /**
     * Where the browser comes back to make this request again, after it signed in, consented or
     * stepped up. A pushed request comes back pushed again — by reference, its parameters never in
     * the address bar — under a new handle that lives as long as the login state holding it; the
     * one it came under is spent, so it yields no second request.
     *
     * @param string|null $pushed The handle of the pushed request this is, if it is one.
     */
    private function resume(
        AuthorizationRequest $request,
        RequestParameters $parameters,
        Client $client,
        ?string $pushed,
    ): string {
        if ($pushed === null) {
            return $request->resumption($parameters);
        }

        $_ = $this->pushedRequests->spend($pushed);
        $handle = $this->secrets->token();
        $this->pushedRequests->push(
            $handle,
            new PushedAuthorizationRequest($client->id, $parameters->pairs()),
            LoginState::LIFETIME_SECONDS,
        );

        return $request->byReference($client->id, PushedAuthorizationRequest::uriFor($handle));
    }

    /**
     * Whether the person behind the request has to sign in again although they are
     * signed in: the client asked to see them (`prompt=login`, `select_account`), or their
     * sign-in is older than `max_age` — or of an unknown time, which no `max_age` accepts.
     */
    private function mustBeSeenAgain(EndUser $endUser, Prompt $prompt, ?MaxAge $maxAge): bool
    {
        return $prompt->demandsSignIn()
            || ($maxAge?->isExceededBy($endUser->session?->authenticatedAt, $this->clock->now()) ?? false);
    }

    /**
     * A signed-in person who falls short of the requirement: asked for one more factor, unless
     * nothing may be shown, or nothing they hold would be enough. The request is resumed as it
     * is, `acr_values` included, so the endpoint decides again once the session is raised.
     */
    private function stepUp(
        AuthorizationRequest $request,
        EndUser $endUser,
        Client $client,
        string $redirectUri,
        ?string $state,
        AuthenticationRequirement $requirement,
        Prompt $prompt,
        ?string $pushed,
    ): StepUpRequired|EnrolmentRequired|RequestRefused {
        if ($prompt->forbidsInteraction()) {
            return new RequestRefused(
                $redirectUri,
                OAuth2Error::interactionRequired("The sign-in must be stronger, and 'prompt=none' forbids asking."),
                $state,
            );
        }

        // Without a session (the development auto-login) there is nothing to raise.
        $session = $endUser->session;
        $resumed = $this->resume($request, $request->parameters, $client, $pushed);
        $challenge = $session === null ? null : ($this->beginStepUp)($session, $requirement, $resumed, $client->id);
        if ($challenge !== null) {
            return new StepUpRequired($challenge);
        }
        $enrolment = $session === null ? null : ($this->beginEnrolment)($session, $requirement, $resumed, $client->id);
        if ($enrolment !== null) {
            return new EnrolmentRequired($enrolment);
        }

        return new RequestRefused(
            $redirectUri,
            OAuth2Error::unmetAuthenticationRequirements('The person cannot sign in as strongly as the request asks.'),
            $state,
        );
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
        ?string $pushed,
    ): ConsentRequired {
        $handle = $this->secrets->token();
        $this->consentStates->park($handle, new PendingConsent(
            $this->resume(
                $request,
                $request->parameters->with('prompt', $prompt->without(Prompt::CONSENT)),
                $client,
                $pushed,
            ),
            $redirectUri,
            $state,
            $endUser->userId,
            $client->id,
            $scope,
            $target?->id,
        ));

        return new ConsentRequired($handle);
    }
}
