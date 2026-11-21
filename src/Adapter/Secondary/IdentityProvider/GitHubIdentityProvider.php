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
 * Sign in with GitHub: an OAuth App's code flow, then the REST API.
 *
 * The numeric account `id` from `GET /user` is the subject — the login can be renamed.
 * The address comes from `GET /user/emails` (the `user:email` scope): the profile's public
 * address may be absent and says nothing about verification, while that list flags each
 * address `primary` and `verified`. Only the primary address, when verified, counts.
 */
final readonly class GitHubIdentityProvider implements IdentityProvider
{
    public const string NAME = 'github';

    public const string AUTHORIZATION_ENDPOINT = 'https://github.com/login/oauth/authorize';

    public const string TOKEN_ENDPOINT = 'https://github.com/login/oauth/access_token';

    public const string USER_ENDPOINT = 'https://api.github.com/user';

    public const string EMAILS_ENDPOINT = 'https://api.github.com/user/emails';

    public const string SCOPE = 'read:user user:email';

    /** GitHub's media type for the REST API. */
    private const string ACCEPT = 'application/vnd.github+json';

    private AuthorizationCodeExchange $exchange;

    /**
     * @param non-empty-string $clientId     `CLAVIA_GITHUB_CLIENT_ID`.
     * @param non-empty-string $clientSecret `CLAVIA_GITHUB_CLIENT_SECRET`.
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

        $profile = $this->http->getWithToken(self::NAME, self::USER_ENDPOINT, $token, self::ACCEPT);
        $id = $profile['id'] ?? null;
        if (! is_int($id) || $id <= 0) {
            $this->http->fail(self::NAME, 'the profile carried no account id.');
        }

        $primary = $this->primaryVerifiedEmail(
            $this->http->getWithToken(self::NAME, self::EMAILS_ENDPOINT, $token, self::ACCEPT),
        );

        try {
            return AssertedIdentity::of($this->name(), (string) $id, $primary, $primary !== null);
        } catch (InvalidValue) {
            $this->http->fail(self::NAME, 'the profile carried an unusable account id.');
        }
    }

    /**
     * @param array<array-key, mixed> $emails
     */
    private function primaryVerifiedEmail(array $emails): ?string
    {
        /** @var mixed $entry */
        foreach ($emails as $entry) {
            if (! is_array($entry) || ($entry['primary'] ?? false) !== true || ($entry['verified'] ?? false) !== true) {
                continue;
            }
            /** @var mixed $address */
            $address = $entry['email'] ?? null;

            return is_string($address) ? $address : null;
        }

        return null;
    }
}
