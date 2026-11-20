<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Application\Port\IdentityProviderFailed;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;

/**
 * The provider-independent half of the authorization code grant, client side (RFC 6749
 * §4.1): building the authorization URL, and redeeming the code for an access token
 * with the client secret in the body (`client_secret_post`, §2.3.1) and the PKCE
 * verifier (RFC 7636 §4.5).
 */
final readonly class AuthorizationCodeExchange
{
    /**
     * @param non-empty-string $clientId
     * @param non-empty-string $clientSecret
     */
    public function __construct(
        private ProviderHttp $http,
        private string $provider,
        private string $authorizationEndpoint,
        private string $tokenEndpoint,
        private string $scope,
        private string $clientId,
        #[\SensitiveParameter] private string $clientSecret,
    ) {
    }

    public function authorizationUrl(string $redirectUri, string $state, CodeChallenge $challenge): string
    {
        return $this->authorizationEndpoint . '?' . http_build_query([
            'response_type' => 'code',
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUri,
            'scope' => $this->scope,
            'state' => $state,
            'code_challenge' => $challenge->value,
            'code_challenge_method' => 'S256',
        ], '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @return non-empty-string The access token.
     *
     * @throws IdentityProviderFailed
     */
    public function accessToken(
        #[\SensitiveParameter] string $code,
        string $redirectUri,
        CodeVerifier $verifier,
    ): string {
        $answer = $this->http->postForm($this->provider, $this->tokenEndpoint, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'code_verifier' => $verifier->value,
        ]);

        // GitHub reports a refused code with 200 and an `error` member.
        $token = $answer['access_token'] ?? null;
        if (! is_string($token) || $token === '') {
            $this->http->fail($this->provider, 'the token endpoint returned no access token.');
        }

        return $token;
    }
}
