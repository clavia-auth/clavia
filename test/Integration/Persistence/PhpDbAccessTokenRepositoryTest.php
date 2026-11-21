<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Persistence;

use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbAccessTokenRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbAuthorizationCodeRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbClientRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbRefreshTokenRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbTransactionManager;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbUserRepository;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Contract\AccessTokenRepositoryContract;
use ClaviaTest\Support\Contract\RefreshTokenRepositoryContract;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use LogicException;

/**
 * The PostgreSQL access and refresh token repositories against their contracts.
 */
final class PhpDbAccessTokenRepositoryTest extends IntegrationTestCase
{
    use AccessTokenRepositoryContract;
    use RefreshTokenRepositoryContract;

    #[\Override]
    protected function tokens(): AccessTokenRepository
    {
        return new PhpDbAccessTokenRepository(TestStorage::database());
    }

    #[\Override]
    protected function refreshTokens(): RefreshTokenRepository
    {
        return new PhpDbRefreshTokenRepository(TestStorage::database());
    }

    #[\Override]
    protected function transactional(callable $work): mixed
    {
        return new PhpDbTransactionManager(TestStorage::database())->transactional($work);
    }

    public function testARefreshTokenCanOnlyBeLockedInsideATransaction(): void
    {
        $this->expectException(LogicException::class);

        $this->refreshTokens()->lockForRefresh(Digest::of('anything'));
    }

    public function testARefreshTokenItselfIsNeverStored(): void
    {
        $this->refreshTokens()->add(RefreshToken::startFamily(
            RefreshTokenId::generate(new SeededRandomSource(3)),
            Digest::of('the-plain-refresh-token'),
            $this->aStoredCode('code-1'),
            ScopeSet::fromString('openid'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            60,
            120,
        ));

        $row = TestStorage::database()->fetchOne('SELECT * FROM oauth2_refresh_tokens');

        self::assertNotNull($row);
        self::assertStringNotContainsString('the-plain-refresh-token', implode('|', array_map(strval(...), $row)));
    }

    #[\Override]
    protected function aStoredCode(string $value): AuthorizationCode
    {
        $database = TestStorage::database();
        $clientId = ClientId::fromString('owner-client');
        $userId = UserId::generate(new SeededRandomSource(7));
        $at = new DateTimeImmutable('2026-01-15T10:00:00Z');

        $clients = new PhpDbClientRepository($database, new PhpDbTransactionManager($database));
        if ($clients->find($clientId) === null) {
            $clients->save(Client::register(
                $clientId,
                'Owner',
                ClientType::Public,
                ClientAuthMethod::None,
                null,
                [Url::fromString('https://app.example/cb')],
                [GrantType::AuthorizationCode],
                [ResponseType::Code],
                $at,
            ));
            new PhpDbUserRepository($database)->save(User::register($userId, 'owner@example.com', null, $at));
        }

        $code = AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(crc32($value))),
            Digest::of($value),
            $clientId,
            $userId,
            'https://app.example/cb',
            ScopeSet::fromString('openid'),
            CodeChallenge::fromString(str_repeat('a', 43)),
            null,
            null,
            AuthenticationContext::unknown(),
            $at,
            60,
        );
        new PhpDbAuthorizationCodeRepository($database)->add($code);

        return $code;
    }

    public function testTheTokenItselfIsNeverStored(): void
    {
        $this->tokens()->add($this->aToken('the-plain-token', $this->aStoredCode('code-1')));

        $row = TestStorage::database()->fetchOne('SELECT * FROM oauth2_access_tokens');

        self::assertNotNull($row);
        self::assertSame('Bearer', $row['token_type']);
        self::assertStringNotContainsString('the-plain-token', implode('|', array_map(strval(...), $row)));
    }
}
