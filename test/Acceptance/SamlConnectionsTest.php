<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use ClaviaTest\Support\Fake\FakeHttpClient;
use Clavia\Adapter\Primary\Http\Auth\Saml\SamlMetadataHandler;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Saml\HttpSamlMetadataSource;
use Clavia\Adapter\Secondary\Saml\Postgres\PostgresServiceProviderKeyStore;
use Clavia\Application\Connection\Saml\RotateServiceProviderKeys;
use Clavia\Application\Port\Saml\SamlMetadataSource;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeSamlMetadataSource;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\Saml\TestIdentityProvider as Idp;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\RequestFactory;
use Psr\Http\Message\ResponseInterface;

/**
 * SAML connections through the real routes (#125, docs/design/saml-connections.md §5.2, §5.4):
 * registered from an identity provider's metadata, refreshed from its URL, and this server's own
 * metadata handed out for it.
 */
final class SamlConnectionsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string METADATA_URL = 'https://idp.acme.example/metadata';

    private FakeSamlMetadataSource $source;

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->source = new FakeSamlMetadataSource();
        $this->container()->setService(SamlMetadataSource::class, $this->source);
        $this->container()->setService(ServiceProviderKeyStore::class, new PostgresServiceProviderKeyStore(
            $this->container()->get(Database::class),
            $this->container()->get(SecretCipher::class),
            $this->container()->get(RandomSource::class),
            'auth.clavia.test',
            2048,
        ));
        $this->adminToken();
    }

    public function testAnIdentityProviderIsRegisteredFromItsMetadataDocument(): void
    {
        $created = $this->registerSaml([
            'metadata' => Idp::vendorMetadata('entra'),
            'subject_attribute' => 'objectidentifier',
        ]);

        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
        /** @var array{strategy: string, configured: bool, saml: array<string, mixed>} $connection */
        $connection = self::document($created);
        self::assertSame('saml', $connection['strategy']);
        self::assertTrue($connection['configured'], 'Its settings are its provider.');
        $saml = $connection['saml'];
        self::assertSame('https://sts.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47/', $saml['entity_id']);
        self::assertNull($saml['metadata_url']);
        self::assertSame('objectidentifier', $saml['subject_attribute']);
        self::assertSame([[
            'sha256' => hash('sha256', (string) base64_decode(Idp::der(Idp::rsa()['certificate']), true)),
            'not_after' => $saml['certificates'][0]['not_after'] ?? null,
        ]], $saml['certificates']);
        self::assertSame([
            'entity_id' => 'https://auth.clavia.test/auth/saml/acme',
            'acs_url' => 'https://auth.clavia.test/auth/saml/acme/acs',
            'metadata_url' => 'https://auth.clavia.test/auth/saml/acme/metadata',
            'warning' => $saml['service_provider']['warning'] ?? null,
        ], $saml['service_provider']);
        self::assertStringContainsString('saml-keys:generate', (string) $saml['service_provider']['warning']);
        self::assertStringNotContainsString('BEGIN CERTIFICATE', (string) $created->getBody());
    }

    public function testEachRefusalPointsAtItsField(): void
    {
        $this->source->documents[self::METADATA_URL] = Idp::metadata([Idp::ec()['certificate']]);
        $cases = [
            '/saml/metadata' => ['metadata' => Idp::metadata()],
            '/saml/metadata_url' => ['metadata_url' => self::METADATA_URL],
            '/saml/metadata ' => [],
            '/saml/metadata_url ' => ['metadata_url' => 'https://unreachable.example/metadata'],
            '/saml' => ['metadata' => Idp::metadata([Idp::rsa()['certificate']]), 'name_id_format' => 'email'],
        ];
        foreach ($cases as $pointer => $saml) {
            $refused = $this->registerSaml($saml);
            self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $refused->getStatusCode(), $pointer);
            /** @var array{errors: list<array{pointer: string, detail: string}>} $problem */
            $problem = self::document($refused);
            self::assertSame(trim($pointer), $problem['errors'][0]['pointer'], (string) $refused->getBody());
        }
        self::assertSame(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/connections', [
                'name' => 'pool',
                'display_name' => 'Pool',
                'strategy' => 'database',
                'saml' => ['metadata' => Idp::metadata([Idp::rsa()['certificate']])],
            ])->getStatusCode(),
            'Only a SAML connection takes saml.',
        );
    }

    public function testAPrivateMetadataUrlIsRefusedBeforeAnythingIsFetched(): void
    {
        $this->container()->setService(SamlMetadataSource::class, new HttpSamlMetadataSource(
            new FakeHttpClient(),
            new RequestFactory(),
            new OutboundUrlPolicy(false, static fn (): array => []),
        ));

        $refused = $this->registerSaml(['metadata_url' => 'https://10.0.0.7/metadata']);

        self::assertSame(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, $refused->getStatusCode());
        self::assertSame('/saml/metadata_url', self::document($refused)['errors'][0]['pointer'] ?? null);
    }

    public function testARefreshReadsTheMetadataUrlAgain(): void
    {
        $this->source->documents[self::METADATA_URL] = Idp::metadata([Idp::rsa()['certificate']]);
        $created = $this->registerSaml(['metadata_url' => self::METADATA_URL]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode());
        $rolledOver = [Idp::attacker()['certificate'], Idp::rsa()['certificate']];
        $this->source->documents[self::METADATA_URL] = Idp::metadata($rolledOver);

        $refreshed = $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/connections/acme/refresh-metadata');

        self::assertSame(StatusCodeInterface::STATUS_OK, $refreshed->getStatusCode(), (string) $refreshed->getBody());
        /** @var array{saml: array{certificates: list<array{sha256: string}>}} $connection */
        $connection = self::document($refreshed);
        self::assertCount(2, $connection['saml']['certificates']);
        self::assertCount(2, $this->source->fetched);
        self::assertSame(
            '["saml.metadata"]',
            TestStorage::database()->fetchValue(
                "SELECT details->>'fields' FROM audit_events WHERE type = 'connection.updated'",
            ),
            'Recorded, by what changed.',
        );
    }

    public function testOnlyASamlConnectionFromAUrlIsRefreshed(): void
    {
        $this->registerSaml(['metadata' => Idp::metadata([Idp::rsa()['certificate']])]);

        $refresh = fn (string $name): int
            => $this->api(
                RequestMethodInterface::METHOD_POST,
                '/api/v1/connections/' . $name . '/refresh-metadata',
            )->getStatusCode();
        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $refresh('acme'), 'From a document.');
        self::assertSame(StatusCodeInterface::STATUS_CONFLICT, $refresh('password'), 'Not SAML.');
        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $refresh('nobody'));
    }

    public function testThisServersMetadataCarriesItsCurrentAndNextCertificates(): void
    {
        $this->registerSaml(['metadata' => Idp::metadata([Idp::rsa()['certificate']])]);
        $rotate = $this->container()->get(RotateServiceProviderKeys::class);
        $rotate();

        $metadata = $this->get('/auth/saml/acme/metadata');

        self::assertSame(StatusCodeInterface::STATUS_OK, $metadata->getStatusCode());
        self::assertSame('application/samlmetadata+xml', $metadata->getHeaderLine('Content-Type'));
        self::assertSame(
            'public, max-age=' . SamlMetadataHandler::CACHE_MAX_AGE,
            $metadata->getHeaderLine('Cache-Control'),
        );
        $xml = (string) $metadata->getBody();
        self::assertStringContainsString('entityID="https://auth.clavia.test/auth/saml/acme"', $xml);
        self::assertStringContainsString('Location="https://auth.clavia.test/auth/saml/acme/acs"', $xml);
        self::assertSame(2, substr_count($xml, '<md:KeyDescriptor'), 'A pair now.');
        $rotate();
        $withNext = (string) $this->get('/auth/saml/acme/metadata')->getBody();
        self::assertSame(4, substr_count($withNext, '<md:KeyDescriptor'), 'And the next one.');

        $this->api(RequestMethodInterface::METHOD_PATCH, '/api/v1/connections/acme', ['is_enabled' => false]);
        foreach (['acme', 'password', 'nobody'] as $name) {
            self::assertSame(
                StatusCodeInterface::STATUS_NOT_FOUND,
                $this->get('/auth/saml/' . $name . '/metadata')->getStatusCode(),
                $name . ': disabled, not SAML, unknown.',
            );
        }
    }

    /** @param array<string, mixed> $saml */
    private function registerSaml(array $saml): ResponseInterface
    {
        return $this->api(RequestMethodInterface::METHOD_POST, '/api/v1/connections', [
            'name' => 'acme',
            'display_name' => 'Acme staff',
            'strategy' => 'saml',
            'saml' => (object) $saml,
        ]);
    }
}
