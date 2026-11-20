<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Persistence;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Url;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbAuthorizationCodeRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbClientRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbTransactionManager;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbUserRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PostgresUrl;
use ClaviaTest\Support\Contract\AuthorizationCodeRepositoryContract;
use ClaviaTest\Support\Contract\ClientRepositoryContract;
use ClaviaTest\Support\Contract\UserRepositoryContract;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use ClaviaTest\Support\TestStorage;
use DateTimeImmutable;
use Throwable;

/**
 * The PostgreSQL repositories against the contracts their in-memory doubles also pass,
 * plus what only a real database can show: its constraints.
 */
final class PhpDbRepositoriesTest extends IntegrationTestCase
{
    use UserRepositoryContract;
    use ClientRepositoryContract;
    use AuthorizationCodeRepositoryContract;

    #[\Override]
    protected function users(): UserRepository
    {
        return new PhpDbUserRepository(TestStorage::database());
    }

    #[\Override]
    protected function clients(): ClientRepository
    {
        return new PhpDbClientRepository(TestStorage::database());
    }

    #[\Override]
    protected function codes(): AuthorizationCodeRepository
    {
        return new PhpDbAuthorizationCodeRepository(TestStorage::database());
    }

    #[\Override]
    protected function transactional(callable $work): mixed
    {
        return new PhpDbTransactionManager(TestStorage::database())->transactional($work);
    }

    #[\Override]
    protected function anOwner(): array
    {
        $clientId = ClientId::fromString('owner-client');
        $userId = UserId::generate(new SeededRandomSource(7));

        if ($this->clients()->find($clientId) === null) {
            $this->clients()->save(Client::register(
                $clientId,
                'Owner',
                ClientType::Public,
                ClientAuthMethod::None,
                null,
                [Url::fromString('https://app.example/cb')],
                [GrantType::AuthorizationCode],
                [ResponseType::Code],
                new DateTimeImmutable('2026-01-15T10:00:00Z'),
            ));
            $this->users()->save(User::register(
                $userId,
                'owner@example.com',
                null,
                new DateTimeImmutable('2026-01-15T10:00:00Z'),
            ));
        }

        return [$clientId, $userId];
    }

    public function testTwoAccountsCannotShareAnEmail(): void
    {
        $this->users()->save($this->aUser('jane@example.com'));
        $twin = User::register(
            UserId::generate(new SeededRandomSource(12345)),
            'jane@example.com',
            null,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );

        try {
            $this->users()->save($twin);
            self::fail('The second account was accepted.');
        } catch (Throwable $refused) {
            self::assertStringContainsString('uq_users_email', $this->messages($refused));
        }
    }

    public function testACodeCannotBeStoredTwice(): void
    {
        $this->codes()->add($this->aCode('the-code'));

        try {
            $this->codes()->add($this->aCode('the-code'));
            self::fail('The same code was stored twice.');
        } catch (Throwable $refused) {
            self::assertStringContainsString('oauth2_authorization_codes', $this->messages($refused));
        }
    }

    public function testALockedCodeIsHeldAgainstASecondRedemption(): void
    {
        $this->codes()->add($this->aCode('the-code'));
        $rival = new Database(PostgresUrl::parse(TestEnvironment::databaseUrl()));
        $rival->execute("SET lock_timeout = '150ms'");

        $outcome = $this->transactional(function () use ($rival): string {
            self::assertNotNull($this->codes()->lockForRedemption(Digest::of('the-code')));

            // A second redemption of the same code, on its own connection, has to wait
            // for this one to finish. Here it gives up instead, which is the proof.
            try {
                new PhpDbTransactionManager($rival)->transactional(
                    static fn (): ?AuthorizationCode
                        => new PhpDbAuthorizationCodeRepository($rival)->lockForRedemption(Digest::of('the-code')),
                );

                return 'the rival read the code';
            } catch (Throwable $blocked) {
                return $this->messages($blocked);
            }
        });

        self::assertStringContainsString('lock timeout', $outcome);

        // Once the first transaction has ended the rival gets through.
        $after = new PhpDbTransactionManager($rival)->transactional(
            static fn (): ?AuthorizationCode
                => new PhpDbAuthorizationCodeRepository($rival)->lockForRedemption(Digest::of('the-code')),
        );
        self::assertNotNull($after);
    }

    public function testListsAreStoredAsJsonArrays(): void
    {
        $this->clients()->save($this->aPublicClient('spa', 'My SPA'));

        $row = TestStorage::database()->fetchOne(
            'SELECT redirect_uris::text AS redirect_uris, grant_types::text AS grant_types FROM oauth2_clients',
        );

        self::assertNotNull($row);
        self::assertSame(
            ['https://app.example/cb?x=1&y=%C3%A9', 'http://localhost:3000/callback'],
            json_decode((string) $row['redirect_uris'], true),
        );
        self::assertSame(['authorization_code'], json_decode((string) $row['grant_types'], true));
    }

    public function testTheCodeItselfIsNeverStored(): void
    {
        $this->codes()->add($this->aCode('the-plain-code'));

        $row = TestStorage::database()->fetchOne('SELECT * FROM oauth2_authorization_codes');

        self::assertNotNull($row);
        self::assertStringNotContainsString('the-plain-code', implode('|', array_map(strval(...), $row)));
    }

    private function messages(Throwable $error): string
    {
        $messages = [];
        for ($current = $error; $current !== null; $current = $current->getPrevious()) {
            $messages[] = $current->getMessage();
        }

        return implode("\n", $messages);
    }
}
