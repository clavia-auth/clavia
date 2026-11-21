<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\IdentityProvider;

use Clavia\Application\Port\IdentityProvider;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Sign in with Google: OAuth 2.0 with PKCE, then OpenID Connect userinfo, whose `sub` is
 * the subject and whose `email_verified` is Google's own statement about the address.
 *
 * Userinfo is called over TLS with the access token just issued, so its answer is
 * Google's without verifying an ID token's signature — and no `nonce` is needed to bind
 * one to this sign-in.
 */
final readonly class GoogleIdentityProvider implements IdentityProvider
{
    public const string NAME = 'google';

    public const string AUTHORIZATION_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';

    public const string TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

    public const string USERINFO_ENDPOINT = 'https://openidconnect.googleapis.com/v1/userinfo';

    public const string SCOPE = 'openid email profile';

    private AuthorizationCodeExchange $exchange;

    /**
     * @param non-empty-string $clientId     `CLAVIA_GOOGLE_CLIENT_ID`.
     * @param non-empty-string $clientSecret `CLAVIA_GOOGLE_CLIENT_SECRET`.
     */
    public function __construct(
        private ProviderHttp $http,
        string $clientId,
        #[\SensitiveParameter] string $clientSecret,
    ) {
        $this->exchange = new AuthorizationCodeExchange(
            $http,
            self::NAME,
            self::AUTHORIZATION_ENDPOINT,
            self::TOKEN_ENDPOINT,
            self::SCOPE,
            $clientId,
            $clientSecret,
        );
    }

    #[\Override]
    public function name(): ConnectionName
    {
        return ConnectionName::fromString(self::NAME);
    }

    #[\Override]
    public function authorizationUrl(
        string $redirectUri,
        string $state,
        CodeChallenge $challenge,
        Nonce $nonce,
    ): string {
        return $this->exchange->authorizationUrl($redirectUri, $state, $challenge);
    }

    #[\Override]
    public function identify(
        #[\SensitiveParameter] string $code,
        string $redirectUri,
        CodeVerifier $verifier,
        Nonce $nonce,
    ): AssertedIdentity {
        $token = $this->exchange->accessToken($code, $redirectUri, $verifier);
        $claims = $this->http->getWithToken(self::NAME, self::USERINFO_ENDPOINT, $token);

        $subject = $claims['sub'] ?? null;
        if (! is_string($subject)) {
            $this->http->fail(self::NAME, 'userinfo carried no subject.');
        }
        /** @var mixed $email */
        $email = $claims['email'] ?? null;

        try {
            return AssertedIdentity::of(
                $this->name(),
                $subject,
                is_string($email) ? $email : null,
                ($claims['email_verified'] ?? false) === true,
            );
        } catch (InvalidValue) {
            $this->http->fail(self::NAME, 'userinfo carried an unusable subject.');
        }
    }
}
