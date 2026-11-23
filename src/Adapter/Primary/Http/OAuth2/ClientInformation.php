<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\Registration\ClientRegistration;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Url;

/**
 * The client information response (RFC 7591 §3.2.1, RFC 7592 §3): every field registered, and
 * nothing this server ignored. The secrets appear only when they were just handed out.
 */
final class ClientInformation
{
    private function __construct()
    {
    }

    /**
     * @param non-empty-string $issuer
     * @param string|null      $clientSecret            Only at registration.
     * @param string|null      $registrationAccessToken At registration, and after each update.
     *
     * @return array<string, mixed>
     */
    public static function of(
        Client $client,
        ClientRegistration $registration,
        string $issuer,
        #[\SensitiveParameter] ?string $clientSecret = null,
        #[\SensitiveParameter] ?string $registrationAccessToken = null,
    ): array {
        $uris = static fn (array $list): array => array_map(static fn (Url $uri): string => $uri->value, $list);
        $view = ['client_id' => $client->id->value];
        if ($clientSecret !== null) {
            $view['client_secret'] = $clientSecret;
            // §3.2.1: zero, the secret never expires.
            $view['client_secret_expires_at'] = 0;
        }
        $view['client_id_issued_at'] = $registration->registeredAt->getTimestamp();
        if ($registrationAccessToken !== null) {
            $view['registration_access_token'] = $registrationAccessToken;
        }
        $view += [
            'registration_client_uri' => self::uriOf($client, $issuer),
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

    /**
     * The client's configuration endpoint (RFC 7592 §2), under the registration endpoint.
     *
     * @param non-empty-string $issuer
     */
    public static function uriOf(Client $client, string $issuer): string
    {
        return $issuer . ProviderMetadata::REGISTRATION_ENDPOINT . '/' . rawurlencode($client->id->value);
    }
}
