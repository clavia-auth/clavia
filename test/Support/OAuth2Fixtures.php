<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\Url;
use Psr\Http\Message\ResponseInterface;

/**
 * The users, clients and request builders the OAuth2 acceptance tests share.
 *
 * Everything is created through the real repositories of the application under test.
 *
 * @psalm-require-extends AcceptanceTestCase
 */
trait OAuth2Fixtures
{
    protected const string TEST_USER_EMAIL = 'user@clavia.dev';
    protected const string TEST_USER_PASSWORD = 'test-password';
    protected const string TEST_CLIENT_ID = 'test-public-client';
    protected const string TEST_REDIRECT_URI = 'https://client.test/callback';
    protected const string TEST_POST_LOGOUT_REDIRECT_URI = 'https://client.test/signed-out';
    protected const string TEST_CONFIDENTIAL_CLIENT_ID = 'test-confidential-client';
    protected const string TEST_CLIENT_SECRET = 'test-client-secret';

    /** A seeded, active end user. */
    protected function user(): User
    {
        /** @var UserRepository $users */
        $users = $this->container()->get(UserRepository::class);

        $existing = $users->findByEmail(ConnectionName::defaultPool(), self::TEST_USER_EMAIL);
        if ($existing !== null) {
            return $existing;
        }

        /** @var PasswordHasher $hasher */
        $hasher = $this->container()->get(PasswordHasher::class);
        /** @var RandomSource $random */
        $random = $this->container()->get(RandomSource::class);
        /** @var Clock $clock */
        $clock = $this->container()->get(Clock::class);

        $user = User::register(
            UserId::generate($random),
            self::TEST_USER_EMAIL,
            $hasher->hash(self::TEST_USER_PASSWORD),
            $clock->now(),
        );
        $users->save($user);

        return $user;
    }

    /**
     * Authenticate through the development auto-login seam, so the OAuth2 tests exercise
     * the authorization flow without depending on the login page.
     */
    protected function loggedIn(): User
    {
        $this->boot(['CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL]);

        return $this->user();
    }

    /** A public client: no secret, PKCE is its only proof of possession. */
    protected function publicClient(): Client
    {
        return $this->register(Client::register(
            ClientId::fromString(self::TEST_CLIENT_ID),
            'Test public client',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString(self::TEST_REDIRECT_URI)],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            $this->now(),
            [Url::fromString(self::TEST_POST_LOGOUT_REDIRECT_URI)],
        ));
    }

    /** The public client, registered for refresh tokens as well. */
    protected function refreshingClient(): Client
    {
        return $this->register(Client::register(
            ClientId::fromString(self::TEST_CLIENT_ID),
            'Test public client',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString(self::TEST_REDIRECT_URI)],
            [GrantType::AuthorizationCode, GrantType::RefreshToken],
            [ResponseType::Code],
            $this->now(),
        ));
    }

    /**
     * A confidential client, used to prove PKCE is required of everyone.
     *
     * @param list<GrantType> $grantTypes
     */
    protected function confidentialClient(array $grantTypes = [GrantType::AuthorizationCode]): Client
    {
        /** @var PasswordHasher $hasher */
        $hasher = $this->container()->get(PasswordHasher::class);

        return $this->register(Client::register(
            ClientId::fromString(self::TEST_CONFIDENTIAL_CLIENT_ID),
            'Test confidential client',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretPost,
            $hasher->hash(self::TEST_CLIENT_SECRET),
            [Url::fromString(self::TEST_REDIRECT_URI)],
            $grantTypes,
            [ResponseType::Code],
            $this->now(),
        ));
    }

    /**
     * A `(code_verifier, code_challenge)` pair using S256.
     *
     * @return array{0: string, 1: string}
     */
    protected function makePkcePair(): array
    {
        /** @var RandomSource $random */
        $random = $this->container()->get(RandomSource::class);
        $verifier = CodeVerifier::generate($random);

        return [$verifier->value, CodeChallenge::forVerifier($verifier)->value];
    }

    /**
     * A valid authorization request, before any overrides are applied. An override set
     * to null removes the parameter.
     *
     * @param array<string, string|null> $overrides
     *
     * @return array<string, string>
     */
    protected function authorizeParams(?string $challenge = null, array $overrides = []): array
    {
        $params = [
            'response_type' => 'code',
            'client_id' => self::TEST_CLIENT_ID,
            'redirect_uri' => self::TEST_REDIRECT_URI,
            'scope' => 'openid profile',
            'state' => 'test-state-value',
        ];
        if ($challenge !== null) {
            $params['code_challenge'] = $challenge;
            $params['code_challenge_method'] = 'S256';
        }

        return array_filter(array_merge($params, $overrides), static fn (?string $value): bool => $value !== null);
    }

    /** Pull the authorization code out of a redirect to the client. */
    protected function extractCode(ResponseInterface $response): string
    {
        self::assertSame(302, $response->getStatusCode(), 'expected a redirect: ' . (string) $response->getBody());
        $query = self::locationQuery($response);
        self::assertArrayHasKey('code', $query, 'no code in redirect: ' . $response->getHeaderLine('Location'));

        return $query['code'];
    }

    /**
     * A valid token request for `$code`, before any overrides are applied. An override
     * set to null removes the parameter.
     *
     * @param array<string, string|null> $overrides
     *
     * @return array<string, string>
     */
    protected function tokenRequest(string $code, ?string $verifier, array $overrides = []): array
    {
        $data = [
            'grant_type' => 'authorization_code',
            'client_id' => self::TEST_CLIENT_ID,
            'redirect_uri' => self::TEST_REDIRECT_URI,
            'code' => $code,
            'code_verifier' => $verifier,
        ];

        return array_filter(array_merge($data, $overrides), static fn (?string $value): bool => $value !== null);
    }

    /**
     * Run the authorization request and return the code it issues.
     *
     * @param array<string, string|null> $overrides
     */
    protected function authorizeAndGetCode(string $challenge, array $overrides = []): string
    {
        return $this->extractCode($this->get('/oauth2/authorize', $this->authorizeParams($challenge, $overrides)));
    }

    /**
     * The only row of a table, as an associative array.
     *
     * @return array<string, mixed>
     */
    protected function onlyRow(string $table): array
    {
        $rows = TestStorage::database()->fetchAll('SELECT * FROM ' . $table);
        self::assertCount(1, $rows, 'expected exactly one row in ' . $table);

        return $rows[0];
    }

    /**
     * Store it, enabling the built-in connections for a first-party client that lists none
     * — as the migration did for every first-party client when connections came in.
     */
    private function register(Client $client): Client
    {
        if ($client->isFirstParty() && $client->connections === []) {
            $client = $client->withConnections(Clients::builtInConnections($client->id->value));
        }

        /** @var ClientRepository $clients */
        $clients = $this->container()->get(ClientRepository::class);
        $clients->save($client);

        return $client;
    }

    private function now(): \DateTimeImmutable
    {
        /** @var Clock $clock */
        $clock = $this->container()->get(Clock::class);

        return $clock->now();
    }
}
