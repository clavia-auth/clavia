<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Cli\GenerateServiceProviderKeysCommand;
use Clavia\Adapter\Primary\Cli\ListServiceProviderKeysCommand;
use Clavia\Adapter\Primary\Cli\RotateServiceProviderKeysCommand;
use Clavia\Adapter\Secondary\Saml\Postgres\PostgresServiceProviderKeyStore;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\StatusCodeInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * The SAML service provider keys through the real container (#123, docs/design/saml-connections.md
 * §5.1, §6): the console and the Management API, a rotation in steps, never key material.
 */
final class ManagementSamlKeysTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const int DAY = 86_400;
    private const string ARN = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-12345678900';

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        // The real store, with smaller keys: RSA 3072 is the integration test's to prove.
        $this->container()->setService(ServiceProviderKeyStore::class, new PostgresServiceProviderKeyStore(
            $this->container()->get(Database::class),
            $this->container()->get(SecretCipher::class),
            $this->container()->get(RandomSource::class),
            'auth.clavia.test',
            2048,
        ));
    }

    public function testTheConsoleGeneratesListsAndRefusesToReplace(): void
    {
        self::assertStringContainsString(
            'No SAML service provider key.',
            $this->console(ListServiceProviderKeysCommand::class)[1],
        );

        [$status, $generated] = $this->console(GenerateServiceProviderKeysCommand::class);
        self::assertSame(Command::SUCCESS, $status);
        self::assertStringContainsString('Signing key ', $generated);
        self::assertStringContainsString('Encryption key ', $generated);

        self::assertSame(Command::FAILURE, $this->console(GenerateServiceProviderKeysCommand::class)[0]);
        $listed = $this->console(ListServiceProviderKeysCommand::class)[1];
        self::assertStringContainsString('current', $listed);
        self::assertStringContainsString('encryption', $listed);
        self::assertStringNotContainsString('PRIVATE', $listed);

        $rotate = RotateServiceProviderKeysCommand::class;
        self::assertStringContainsString('A next pair is published', $this->console($rotate)[1]);
        self::assertStringContainsString('nothing to do before then', $this->console($rotate)[1]);
    }

    public function testTheApiRotatesInStepsAndShowsCertificatesNeverKeys(): void
    {
        $clock = $this->freezeClock('2026-03-01T09:00:00Z');
        $this->adminToken();

        self::assertSame([], self::document($this->api('GET', '/api/v1/saml-keys')));
        $generated = self::document($this->api('POST', '/api/v1/saml-keys/rotate'));
        self::assertSame('generated', $generated['step']);
        $introduced = self::document($this->api('POST', '/api/v1/saml-keys/rotate'));
        self::assertSame(['introduced', '2026-03-15T09:00:00Z'], [$introduced['step'], $introduced['promotes_at']]);

        $clock->advance(14 * self::DAY);
        $this->adminToken();
        $promoted = $this->api('POST', '/api/v1/saml-keys/rotate');
        self::assertSame(StatusCodeInterface::STATUS_OK, $promoted->getStatusCode(), (string) $promoted->getBody());
        self::assertSame('promoted', self::document($promoted)['step']);

        $listed = $this->api('GET', '/api/v1/saml-keys');
        /** @var list<array{usage: string, status: string, certificate: string, certificate_sha256: string}> $keys */
        $keys = self::document($listed);
        self::assertSame(
            ['current', 'current', 'retired', 'retired'],
            array_map(static fn (array $key): string => $key['status'], $keys),
        );
        self::assertSame(
            hash('sha256', (string) base64_decode($keys[0]['certificate'], true)),
            $keys[0]['certificate_sha256'],
        );
        self::assertStringNotContainsString('PRIVATE', (string) $listed->getBody());
        self::assertStringNotContainsString('private', (string) $listed->getBody());

        self::assertSame(
            1,
            (int) TestStorage::database()->fetchValue(
                'SELECT count(*) FROM audit_events WHERE type = :type',
                ['type' => AuditEventType::SamlKeyGenerated->value],
            ),
        );
        self::assertSame(
            2,
            (int) TestStorage::database()->fetchValue(
                'SELECT count(*) FROM audit_events WHERE type = :type',
                ['type' => AuditEventType::SamlKeyRotated->value],
            ),
        );
    }

    public function testKeysInAKmsAreRotatedThereNotHere(): void
    {
        $this->boot([
            'CLAVIA_SAML_KEY_BACKEND' => 'aws-kms',
            'CLAVIA_SAML_SIGNING_KEY_REF' => self::ARN . '1',
            'CLAVIA_SAML_ENCRYPTION_KEY_REF' => self::ARN . '2',
        ]);
        $this->adminToken();

        $refused = $this->api('POST', '/api/v1/saml-keys/rotate');

        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $refused->getStatusCode());
        self::assertStringContainsString('KMS', (string) $refused->getBody());
        self::assertSame(
            0,
            (int) TestStorage::database()->fetchValue('SELECT count(*) FROM saml_service_provider_keys'),
            'Nothing made here.',
        );
    }

    public function testEachOperationNeedsItsScope(): void
    {
        $this->adminToken(['read:signing_keys']);

        self::assertSame(StatusCodeInterface::STATUS_OK, $this->api('GET', '/api/v1/saml-keys')->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_FORBIDDEN,
            $this->api('POST', '/api/v1/saml-keys/rotate')->getStatusCode(),
        );
    }

    /**
     * @param class-string<Command> $command
     *
     * @return array{0: int, 1: string}
     */
    private function console(string $command): array
    {
        $tester = new CommandTester($this->container()->get($command));
        $status = $tester->execute([]);

        return [$status, $tester->getDisplay(true)];
    }
}
