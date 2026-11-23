<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use Clavia\Adapter\Primary\Http\Shared\AccessTokenCredentials;
use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Adapter\Primary\Http\Shared\ClientAddress;
use Clavia\Application\Clients\Registration\InitialAccessTokenRejected;
use Clavia\Application\Clients\Registration\RegisterClientDynamically;
use Clavia\Application\Clients\Registration\RegistrationRefused;
use Clavia\Application\Clients\Registration\TooManyRegistrations;
use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Domain\OAuth2\BearerTokenError;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /oauth2/register` (RFC 7591 §3): the client's metadata as a JSON object, and an initial
 * access token as `Authorization: Bearer` (RFC 6750 §2.1). Exists only when
 * `CLAVIA_CLIENT_REGISTRATION` is `token`.
 *
 * Translates and nothing more: the token, the policy and the registration are
 * {@see RegisterClientDynamically}'s. The answer is the client as registered (§3.2.1), with its
 * secrets this once; a refusal is an RFC 7591 §3.2.2 document, or an RFC 6750 challenge for the
 * token.
 */
final readonly class ClientRegistrationHandler implements RequestHandlerInterface
{
    /** @param non-empty-string $issuer */
    public function __construct(
        private RegisterClientDynamically $register,
        private OAuth2Responder $responder,
        private BearerChallenger $challenger,
        private string $issuer,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $credentials = AccessTokenCredentials::fromRequest($request);
        } catch (BearerTokenError $error) {
            return $this->challenger->refuse($error);
        }
        // An initial access token is a bearer token: the DPoP scheme names nothing it could be bound to.
        $token = $credentials?->scheme === TokenScheme::Bearer ? $credentials->accessToken : null;

        try {
            $registered = ($this->register)($token, ClientMetadataBody::members($request), ClientAddress::of($request));
        } catch (TooManyRegistrations $refusal) {
            return $this->responder->tooManyRegistrations($refusal->retryAfterSeconds);
        } catch (InitialAccessTokenRejected $refusal) {
            return $credentials === null
                ? $this->challenger->missing()
                : $this->challenger->refuse(BearerTokenError::invalidToken($refusal->getMessage()));
        } catch (RegistrationRefused $refusal) {
            return $this->responder->registrationRefused($refusal);
        }

        return $this->responder->created(ClientInformation::of(
            $registered->client,
            $registered->registration,
            $this->issuer,
            $registered->clientSecret,
            $registered->registrationAccessToken,
        ));
    }
}
