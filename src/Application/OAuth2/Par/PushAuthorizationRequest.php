<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Par;

use Clavia\Application\OAuth2\Authorize\AuthorizationRequestRules;
use Clavia\Application\OAuth2\ClientAuthentication\ClientAuthenticator;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\OAuth2\MaxAge;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\OAuth2\Prompt;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /oauth2/par` (RFC 9126 §2): a client pushes its authorization request over the back
 * channel, and gets a `request_uri` for the browser to carry to the authorization endpoint.
 *
 * The client authenticates as it would at the token endpoint (§2), so a confidential client's
 * request is known to be its own, and a public client names itself with `client_id`. The request
 * is then held to every rule of the authorization endpoint ({@see AuthorizationRequestRules}),
 * and refused here — as a JSON error, §2.3 — rather than later in a browser. Two parameters are
 * refused outright: `request_uri`, which only this endpoint hands out (§2.1), and `request`, since
 * this server takes no request object.
 *
 * What is held is the request without the client's credentials: `client_secret` never reaches
 * storage.
 */
final readonly class PushAuthorizationRequest
{
    /** Every method the token endpoint takes: a public client pushes too (§2). */
    public const array AUTH_METHODS = [
        ClientAuthMethod::ClientSecretBasic,
        ClientAuthMethod::ClientSecretPost,
        ClientAuthMethod::None,
    ];

    /**
     * @param positive-int $lifetimeSeconds How long a `request_uri` is good for (`CLAVIA_PAR_LIFETIME`).
     */
    public function __construct(
        private ClientAuthenticator $authenticator,
        private AuthorizationRequestRules $rules,
        private PushedAuthorizationRequestStore $pushedRequests,
        private SecretGenerator $secrets,
        private int $lifetimeSeconds,
    ) {
    }

    /**
     * @throws OAuth2Error           `invalid_client`, or what the authorization endpoint would answer.
     * @throws TooManyFailedRequests
     */
    public function __invoke(TokenRequest $request): PushedRequestAccepted
    {
        $client = $this->authenticator->authenticate($request->credentials(), self::AUTH_METHODS);
        $parameters = $request->parameters;

        if ($parameters->get('request_uri') !== null) {
            throw OAuth2Error::invalidRequest("A pushed request carries no 'request_uri': this endpoint hands it out.");
        }
        $clientId = $parameters->get('client_id');
        if ($clientId !== null && $clientId !== $client->id->value) {
            throw OAuth2Error::invalidRequest("The 'client_id' is not the client that authenticated.");
        }
        $parameters = $parameters->without('client_secret')->with('client_id', $client->id->value);

        AuthorizationRequestRules::refuseRequestObjects($parameters);
        $this->rules->redirectUri($parameters, $client);
        [$scope] = $this->rules->validate($parameters, $client);
        $nonce = $this->rules->nonce($parameters, $client, $scope);
        AuthorizationRequestRules::challenge($parameters, $client, $nonce);
        Prompt::fromParameter($parameters->get('prompt'));
        MaxAge::fromParameter($parameters->get('max_age'));
        AuthorizationRequestRules::requirement($parameters);

        $handle = $this->secrets->token();
        $this->pushedRequests->push(
            $handle,
            new PushedAuthorizationRequest($client->id, $parameters->pairs()),
            $this->lifetimeSeconds,
        );

        return new PushedRequestAccepted(PushedAuthorizationRequest::uriFor($handle), $this->lifetimeSeconds);
    }
}
