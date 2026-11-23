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
use Clavia\Application\Clients\Registration\ClientRegisteredItself;
use Clavia\Application\Clients\Registration\InitialAccessTokenRejected;
use Clavia\Application\Clients\Registration\RegisterClientDynamically;
use Clavia\Application\Clients\Registration\RegistrationRefused;
use Clavia\Application\Clients\Registration\TooManyRegistrations;
use Clavia\Application\OAuth2\ProtectedResource\TokenScheme;
use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\Url;
use JsonException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

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
            $registered = ($this->register)($token, self::members($request), ClientAddress::of($request));
        } catch (TooManyRegistrations $refusal) {
            return $this->responder->tooManyRegistrations($refusal->retryAfterSeconds);
        } catch (InitialAccessTokenRejected $refusal) {
            return $credentials === null
                ? $this->challenger->missing()
                : $this->challenger->refuse(BearerTokenError::invalidToken($refusal->getMessage()));
        } catch (RegistrationRefused $refusal) {
            return $this->responder->registrationRefused($refusal);
        }

        return $this->responder->created($this->view($registered));
    }

    /**
     * The body's members: a JSON object, sent as `application/json` (RFC 7591 §3). Anything else
     * is read as no member at all, which the policy refuses for want of a `client_name`.
     *
     * @return array<array-key, mixed>
     */
    private static function members(ServerRequestInterface $request): array
    {
        $type = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'))[0]));
        if ($type !== 'application/json') {
            return [];
        }
        try {
            /** @var mixed $body */
            $body = json_decode((string) $request->getBody(), false, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return [];
        }

        return $body instanceof stdClass ? get_object_vars($body) : [];
    }

    /**
     * The client information response (RFC 7591 §3.2.1): every field registered, and nothing
     * this server ignored.
     *
     * @return array<string, mixed>
     */
    private function view(ClientRegisteredItself $registered): array
    {
        $client = $registered->client;
        $uris = static fn (array $list): array => array_map(static fn (Url $uri): string => $uri->value, $list);
        $view = ['client_id' => $client->id->value];
        if ($registered->clientSecret !== null) {
            $view['client_secret'] = $registered->clientSecret;
            // §3.2.1: zero, the secret never expires.
            $view['client_secret_expires_at'] = 0;
        }
        $view += [
            'client_id_issued_at' => $registered->registration->registeredAt->getTimestamp(),
            'registration_access_token' => $registered->registrationAccessToken,
            'registration_client_uri' => $this->issuer . ProviderMetadata::REGISTRATION_ENDPOINT . '/'
                . rawurlencode($client->id->value),
            'client_name' => $client->name,
            'token_endpoint_auth_method' => $client->authMethod->value,
            'grant_types' => array_map(static fn (GrantType $grant): string => $grant->value, $client->grantTypes),
            'response_types' => array_map(
                static fn (ResponseType $type): string => $type->value,
                $client->responseTypes,
            ),
            'redirect_uris' => $uris($client->redirectUris),
        ];
        if ($client->postLogoutRedirectUris !== []) {
            $view['post_logout_redirect_uris'] = $uris($client->postLogoutRedirectUris);
        }
        if ($client->backChannelLogout !== null) {
            $view['backchannel_logout_uri'] = $client->backChannelLogout->uri->value;
            $view['backchannel_logout_session_required'] = $client->backChannelLogout->sessionRequired;
        }
        $view['dpop_bound_access_tokens'] = $client->requiresDpop;

        return $view;
    }
}
