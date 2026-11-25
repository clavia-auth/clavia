<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Persistence;

use ClaviaTest\Support\Contract\ClientRegistrationRepositoryContract;
use ClaviaTest\Support\Contract\InitialAccessTokenRepositoryContract;
use ClaviaTest\Support\Contract\UserJobRepositoryContract;
use ClaviaTest\Support\Contract\WebhookEndpointRepositoryContract;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbAuthorizationCodeRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbClientGrantRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbClientRegistrationRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbClientRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbConnectionRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbConsentRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbExternalIdentityRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbInitialAccessTokenRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbMfaFactorRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbPasskeyRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbRecoveryCodeRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbResourceServerRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbRoleRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbTransactionManager;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbUserJobRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbUserRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PhpDbWebhookEndpointRepository;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PostgresUrl;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\Jobs\UserJobRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Contract\AuthorizationCodeRepositoryContract;
use ClaviaTest\Support\Contract\ClientRepositoryContract;
use ClaviaTest\Support\Contract\ConnectionRepositoryContract;
use ClaviaTest\Support\Contract\ConsentRepositoryContract;
use ClaviaTest\Support\Contract\ExternalIdentityRepositoryContract;
use ClaviaTest\Support\Contract\MfaRepositoriesContract;
use ClaviaTest\Support\Contract\PasskeyRepositoryContract;
use ClaviaTest\Support\Contract\ResourceServerRepositoryContract;
use ClaviaTest\Support\Contract\RoleRepositoryContract;
use ClaviaTest\Support\Contract\UserRepositoryContract;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use ClaviaTest\Support\TestStorage;
use Clavia\Domain\Webhook\WebhookEndpointRepository;
use DateTimeImmutable;
use LogicException;
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
    use ResourceServerRepositoryContract;
    use MfaRepositoriesContract;
    use PasskeyRepositoryContract;
    use ExternalIdentityRepositoryContract;
    use RoleRepositoryContract;
    use ConsentRepositoryContract;
    use ConnectionRepositoryContract;
    use InitialAccessTokenRepositoryContract;
    use WebhookEndpointRepositoryContract;
    use ClientRegistrationRepositoryContract;
    use UserJobRepositoryContract;

    #[\Override]
    protected function connections(): ConnectionRepository
    {
        return new PhpDbConnectionRepository(TestStorage::database());
    }

    #[\Override]
    protected function consents(): ConsentRepository
    {
        return new PhpDbConsentRepository(TestStorage::database());
    }

    #[\Override]
    protected function initialAccessTokens(): InitialAccessTokenRepository
    {
        return new PhpDbInitialAccessTokenRepository(TestStorage::database());
    }

    #[\Override]
    protected function clientRegistrations(): ClientRegistrationRepository
    {
        return new PhpDbClientRegistrationRepository(TestStorage::database());
    }

    #[\Override]
    protected function userJobs(): UserJobRepository
    {
        return new PhpDbUserJobRepository(TestStorage::database());
    }

    #[\Override]
    protected function roles(): RoleRepository
    {
        return new PhpDbRoleRepository(TestStorage::database(), new PhpDbTransactionManager(TestStorage::database()));
    }

    #[\Override]
    protected function users(): UserRepository
    {
        return new PhpDbUserRepository(TestStorage::database());
    }

    #[\Override]
    protected function identities(): ExternalIdentityRepository
    {
        return new PhpDbExternalIdentityRepository(TestStorage::database());
    }

    #[\Override]
    protected function passkeys(): PasskeyRepository
    {
        return new PhpDbPasskeyRepository(TestStorage::database());
    }

    #[\Override]
    protected function factors(): MfaFactorRepository
    {
        return new PhpDbMfaFactorRepository(TestStorage::database());
    }

    #[\Override]
    protected function recoveryCodes(): RecoveryCodeRepository
    {
        return new PhpDbRecoveryCodeRepository(
            TestStorage::database(),
            new PhpDbTransactionManager(TestStorage::database()),
        );
    }

    #[\Override]
    protected function clients(): ClientRepository
    {
        return new PhpDbClientRepository(
            TestStorage::database(),
            new PhpDbTransactionManager(TestStorage::database()),
        );
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
    protected function resourceServers(): ResourceServerRepository
    {
        return new PhpDbResourceServerRepository(
            TestStorage::database(),
            new PhpDbTransactionManager(TestStorage::database()),
        );
    }

    #[\Override]
    protected function clientGrants(): ClientGrantRepository
    {
        return new PhpDbClientGrantRepository(TestStorage::database());
    }

    #[\Override]
    protected function aClient(string $clientId): ClientId
    {
        $id = ClientId::fromString($clientId);
        $this->clients()->save(Client::register(
            $id,
            'Machine',
            ClientType::Confidential,
            ClientAuthMethod::ClientSecretBasic,
            '$hash$',
            [],
            [GrantType::ClientCredentials],
            [],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        return $id;
    }

    public function testAnApiIdentifierIsUniqueAndImmutable(): void
    {
        $at = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $first = ResourceServer::register(
            ResourceServerId::fromString('rs_aaaaaaaaaaaaaaaa'),
            Audience::fromString('https://api.example/'),
            'First',
            [],
            $at,
        );
        $this->resourceServers()->save($first);

        try {
            $this->resourceServers()->save(ResourceServer::register(
                ResourceServerId::fromString('rs_bbbbbbbbbbbbbbbb'),
                Audience::fromString('https://api.example/'),
                'Second',
                [],
                $at,
            ));
            self::fail('Two APIs share an identifier.');
        } catch (Throwable $refused) {
            self::assertStringContainsString('uq_resource_servers_identifier', $this->messages($refused));
        }

        $this->expectException(LogicException::class);
        $this->resourceServers()->save(ResourceServer::register(
            $first->id,
            Audience::fromString('https://elsewhere.example/'),
            'Renamed',
            [],
            $at,
        ));
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

    public function testTwoAccountsInOnePoolCannotShareAnEmail(): void
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
            self::assertStringContainsString('uq_users_connection_email', $this->messages($refused));
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

    public function testAPasskeyGoesWithItsAccount(): void
    {
        $owner = UserId::generate(new SeededRandomSource(21));
        $this->users()->save(User::register($owner, 'ada@example.com', null, new DateTimeImmutable()));
        $passkey = Passkey::register(
            PasskeyId::generate(new SeededRandomSource(22)),
            $owner,
            CredentialId::fromBytes(str_repeat("\x01", 16)),
            CosePublicKey::fromBytes('key'),
            CoseAlgorithm::EdDSA,
            0,
            [],
            null,
            false,
            false,
            PasskeyName::fromString('Key'),
            new DateTimeImmutable(),
        );
        $this->passkeys()->save($passkey);

        $this->users()->delete($owner);

        self::assertNull($this->passkeys()->one($passkey->id));
        self::assertSame(0, $this->passkeys()->countOf($owner));
    }

    public function testThePasskeysTableRefusesWhatTheDomainRefuses(): void
    {
        $owner = UserId::generate(new SeededRandomSource(31));
        $this->users()->save(User::register($owner, 'ada@example.com', null, new DateTimeImmutable()));
        $insert = static fn (string $credentialId, bool $eligible, bool $backedUp, string $name, int $counter): int =>
            TestStorage::database()->execute(
                <<<'SQL'
                    INSERT INTO passkeys (id, user_id, credential_id, public_key, algorithm, sign_count,
                        backup_eligible, backed_up, name, created_at)
                    VALUES (:id, :user_id, decode(:credential_id, 'hex'), decode('00', 'hex'), -8, :counter,
                        :eligible, :backed_up, :name, now())
                    SQL,
                [
                    'id' => PasskeyId::generate(new SeededRandomSource(random_int(1, PHP_INT_MAX)))->value,
                    'user_id' => $owner->value,
                    'credential_id' => $credentialId,
                    'counter' => $counter,
                    'eligible' => $eligible,
                    'backed_up' => $backedUp,
                    'name' => $name,
                ],
            );
        $valid = bin2hex(str_repeat("\x02", 16));

        foreach (
            [
                'ck_passkeys_credential_id_length' => [bin2hex('short'), false, false, 'Key', 0],
                'ck_passkeys_sign_count' => [$valid, false, false, 'Key', -1],
                'ck_passkeys_name_length' => [$valid, false, false, '', 0],
                'ck_passkeys_backup' => [$valid, false, true, 'Key', 0],
            ] as $constraint => $row
        ) {
            try {
                $insert(...$row);
                self::fail('The table accepted a row that breaks ' . $constraint . '.');
            } catch (Throwable $refused) {
                self::assertStringContainsString($constraint, $this->messages($refused));
            }
        }
    }

    private function messages(Throwable $error): string
    {
        $messages = [];
        for ($current = $error; $current !== null; $current = $current->getPrevious()) {
            $messages[] = $current->getMessage();
        }

        return implode("\n", $messages);
    }

    #[\Override]
    protected function webhookEndpoints(): WebhookEndpointRepository
    {
        return new PhpDbWebhookEndpointRepository(TestStorage::database());
    }
}
