<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Saml\Postgres\PostgresServiceProviderKeyStore;
use Clavia\Adapter\Secondary\Saml\Remote\AwsKmsDecryptionKey;
use Clavia\Adapter\Secondary\Saml\Remote\RemoteServiceProviderKeys;
use Clavia\Adapter\Secondary\Signing\Remote\Aws\AwsKmsKey;
use Clavia\Adapter\Secondary\Signing\X509\SelfSignedCertificate;
use Clavia\Application\Connection\Saml\GenerateServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\Fake\FakeKms;
use ClaviaTest\Support\Fake\InMemoryCertificateCache;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\Saml\TestIdentityProvider as Idp;
use DOMDocument;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Signed requests and encrypted assertions end to end (#127, docs/design/saml-connections.md §5.3,
 * §7): this server signs its `AuthnRequest` with its current signing key and decrypts an assertion
 * encrypted to its encryption certificate, with the keys sealed in PostgreSQL and with the keys in a
 * (mocked) KMS; and every SAML failure counts toward the sign-in throttle.
 */
final class SamlEncryptedSignInTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;
    use LoginFixtures;

    private const string SESSION_COOKIE = 'clavia_session';
    private const string ARN = 'arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-12345678900';

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->freezeClock(Idp::NOW);
        $this->container()->setService(ServiceProviderKeyStore::class, new PostgresServiceProviderKeyStore(
            $this->container()->get(Database::class),
            $this->container()->get(SecretCipher::class),
            $this->container()->get(RandomSource::class),
            'auth.clavia.test',
            2048,
        ));
        $this->adminToken();
    }

    public function testWithKeysInPostgresTheRequestIsSignedAndTheAssertionDecrypted(): void
    {
        $this->container()->get(GenerateServiceProviderKeys::class)();

        $this->signsInEncrypted();
    }

    public function testWithKeysInAKmsTheRequestIsSignedAndTheAssertionDecrypted(): void
    {
        $signing = new FakeKms(new LocalHsm(0));
        $encryption = new FakeKms(new LocalHsm(1));
        $encryption->keyUsage = 'ENCRYPT_DECRYPT';
        $this->container()->setService(ServiceProviderKeys::class, new RemoteServiceProviderKeys(
            new AwsKmsKey($signing->client(), self::ARN . '1'),
            new AwsKmsDecryptionKey($encryption->client(), self::ARN . '2'),
            null,
            null,
            [],
            new InMemoryCertificateCache(),
            $this->container()->get(Clock::class),
            $this->container()->get(RandomSource::class),
            'auth.clavia.test',
        ));

        $this->signsInEncrypted();
        self::assertContains('Sign', array_map(static fn ($c): string => $c->getName(), $signing->commands));
        self::assertContains('Decrypt', array_map(static fn ($c): string => $c->getName(), $encryption->commands));
    }

    public function testAPlainAssertionIsRefusedWhenTheConnectionRequiresEncryption(): void
    {
        $this->container()->get(GenerateServiceProviderKeys::class)();
        $this->registerSaml(['require_encryption' => true]);
        [$requestId, $relayState] = $this->start();

        $refused = $this->finish(self::answering($requestId), $relayState);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode());
        self::assertTrue($this->logger->hasRecordContaining('decryption'));
    }

    public function testWithoutKeysTheRequestGoesUnsigned(): void
    {
        $this->registerSaml([]);

        $location = $this->get('/auth/saml/acme')->getHeaderLine('Location');

        self::assertStringNotContainsString('Signature=', $location);
    }

    public function testSamlFailuresCountTowardTheSignInThrottle(): void
    {
        $this->boot(['CLAVIA_LOGIN_MAX_ATTEMPTS' => '2']);
        $this->freezeClock(Idp::NOW);
        $this->adminToken();
        $this->registerSaml([]);
        foreach ([1, 2] as $attempt) {
            $this->clearCookies();
            [$requestId, $relayState] = $this->start();
            $this->finish(self::answering($requestId, ['key' => Idp::attacker()]), $relayState);
        }
        $this->clearCookies();
        [$requestId, $relayState] = $this->start();

        $refused = $this->finish(self::answering($requestId), $relayState);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $refused->getStatusCode(), 'Even a good response.');
        self::assertTrue($this->logger->hasRecordContaining('throttled'));
    }

    private function signsInEncrypted(): void
    {
        $this->registerSaml(['require_encryption' => true, 'require_gcm' => true]);
        $keys = $this->container()->get(ServiceProviderKeys::class)->certificates();
        $signing = $keys->current(ServiceProviderKeyUsage::Signing);
        $encryption = $keys->current(ServiceProviderKeyUsage::Encryption);
        self::assertNotNull($signing);
        self::assertNotNull($encryption);

        $started = $this->get('/auth/saml/acme');
        $location = $started->getHeaderLine('Location');
        // As the identity provider checks it (Bindings §3.4.4.1), with the certificate in our metadata.
        $query = (string) parse_url($location, PHP_URL_QUERY);
        $signed = '/^(SAMLRequest=[^&]+&RelayState=[^&]+&SigAlg=[^&]+)&Signature=([^&]+)$/D';
        self::assertSame(1, preg_match($signed, $query, $parts), $location);
        $certificate = SelfSignedCertificate::pem((string) base64_decode($signing->certificate, true));
        $signature = (string) base64_decode(rawurldecode($parts[2]), true);
        self::assertSame(1, openssl_verify($parts[1], $signature, $certificate, OPENSSL_ALGO_SHA256));
        [$requestId, $relayState] = self::requestOf($location);

        $finished = $this->finish(self::answering($requestId, [
            'encryptTo' => SelfSignedCertificate::pem((string) base64_decode($encryption->certificate, true)),
        ]), $relayState);

        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $finished->getStatusCode(),
            (string) $finished->getBody(),
        );
        self::assertNotNull($this->session($this->cookie(self::SESSION_COOKIE)), 'Signed in.');
    }

    /** @return array{0: string, 1: string} */
    private function start(): array
    {
        $started = $this->get('/auth/saml/acme');
        self::assertSame(
            StatusCodeInterface::STATUS_SEE_OTHER,
            $started->getStatusCode(),
            (string) $started->getBody(),
        );

        return self::requestOf($started->getHeaderLine('Location'));
    }

    /** @return array{0: string, 1: string} The request's id and the RelayState. */
    private static function requestOf(string $location): array
    {
        parse_str((string) parse_url($location, PHP_URL_QUERY), $query);
        $xml = (string) gzinflate((string) base64_decode((string) ($query['SAMLRequest'] ?? ''), true));
        $request = new DOMDocument();
        self::assertTrue($xml !== '' && $request->loadXML($xml));

        return [(string) $request->documentElement?->getAttribute('ID'), (string) ($query['RelayState'] ?? '')];
    }

    private function finish(string $response, string $relayState): ResponseInterface
    {
        $acs = $this->post('/auth/saml/acme/acs', ['SAMLResponse' => $response, 'RelayState' => $relayState]);
        self::assertSame(StatusCodeInterface::STATUS_SEE_OTHER, $acs->getStatusCode(), (string) $acs->getBody());

        return $this->get($acs->getHeaderLine('Location'));
    }

    /** @param array<string, mixed> $options */
    private static function answering(string $requestId, array $options = []): string
    {
        return Idp::response($options + ['inResponseTo' => $requestId, 'confirmationInResponseTo' => $requestId]);
    }

    /** @param array<string, mixed> $options */
    private function registerSaml(array $options): void
    {
        $created = $this->api('POST', '/api/v1/connections', [
            'name' => 'acme',
            'display_name' => 'Acme staff',
            'strategy' => 'saml',
            'is_domain_connection' => true,
            'saml' => (object) ($options + [
                'metadata' => Idp::metadata([Idp::rsa()['certificate']]),
                'email_attribute' => 'email',
            ]),
        ]);
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $created->getStatusCode(), (string) $created->getBody());
    }
}
