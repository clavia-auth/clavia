<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing\Remote;

use Clavia\Adapter\Secondary\Signing\Remote\Azure\AzureKeyVaultKey;
use Clavia\Adapter\Secondary\Signing\Remote\InvalidKeyReference;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Base64Url;
use ClaviaTest\Support\Contract\RemoteSigningKeyContract;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\FakeKeyVault;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\Fake\StaticAccessTokens;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class AzureKeyVaultKeyTest extends TestCase
{
    use RemoteSigningKeyContract;

    private const string VERSION = '0123456789abcdef0123456789abcdef';

    private const string KEY = 'https://clavia-prod.vault.azure.net/keys/signing/' . self::VERSION;

    private FakeKeyVault $vault;

    private FakeHttpClient $http;

    #[\Override]
    protected function setUp(): void
    {
        $this->vault = new FakeKeyVault(self::KEY);
        $this->http = new FakeHttpClient($this->vault);
    }

    #[\Override]
    protected function key(): RemoteSigningKey
    {
        return new AzureKeyVaultKey(
            new JsonApi($this->http, new RequestFactory(), new StreamFactory(), 'Azure Key Vault'),
            new StaticAccessTokens('azure-token'),
            self::KEY,
        );
    }

    #[\Override]
    protected function hsm(): LocalHsm
    {
        return new LocalHsm();
    }

    public function testKeyVaultIsHandedTheDigestUnderTheJoseName(): void
    {
        $digest = hash('sha256', 'header.payload', true);

        $signature = $this->key()->sign($digest, SigningAlgorithm::RS256);

        self::assertSame(new LocalHsm()->signDigest($digest), $signature);
        $request = $this->http->requests[0] ?? null;
        self::assertNotNull($request);
        self::assertSame(self::KEY . '/sign?api-version=7.4', (string) $request->getUri());
        self::assertSame(
            ['alg' => 'RS256', 'value' => Base64Url::encode($digest)],
            json_decode((string) $request->getBody(), true),
        );
    }

    public function testAVaultAndAManagedHsmEachHaveTheirTokenScope(): void
    {
        self::assertSame('https://vault.azure.net/.default', AzureKeyVaultKey::scopeFor(self::KEY));
        self::assertSame(
            'https://managedhsm.azure.net/.default',
            AzureKeyVaultKey::scopeFor('https://hsm.managedhsm.azure.net/keys/signing/' . self::VERSION),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unusableReferences(): iterable
    {
        yield 'without its version' => ['https://clavia-prod.vault.azure.net/keys/signing'];
        yield 'over http' => ['http://clavia-prod.vault.azure.net/keys/signing/' . self::VERSION];
        yield 'on another host' => ['https://vault.example.com/keys/signing/' . self::VERSION];
        yield 'the bare suffix' => ['https://vault.azure.net/keys/signing/' . self::VERSION];
        yield 'a secret' => ['https://clavia-prod.vault.azure.net/secrets/signing/' . self::VERSION];
        yield 'with a query' => ['https://clavia-prod.vault.azure.net/keys/signing/' . self::VERSION . '?x=1'];
        yield 'with a port' => ['https://clavia-prod.vault.azure.net:8443/keys/signing/' . self::VERSION];
    }

    #[DataProvider('unusableReferences')]
    public function testAnythingButAVersionedKeyUrlIsRefused(string $reference): void
    {
        $this->expectException(InvalidKeyReference::class);

        AzureKeyVaultKey::scopeFor($reference);
    }

    public function testAnRsaKeyInSoftwareIsAsGoodAsOneInAnHsm(): void
    {
        $this->vault->keyType = 'RSA';

        self::assertSame(new LocalHsm()->kid(), $this->key()->publicKey(SigningAlgorithm::RS256)->kid);
    }

    public function testADisabledKeyOrOneThatMayNotSignIsReported(): void
    {
        $this->vault->operations = ['encrypt', 'decrypt'];
        try {
            $this->key()->publicKey(SigningAlgorithm::RS256);
            self::fail('A key that may not sign was published.');
        } catch (SigningFailed $refused) {
            self::assertStringContainsString('is not an enabled RSA key that may sign', $refused->getMessage());
        }

        $this->vault->operations = ['sign'];
        $this->vault->enabled = false;
        $this->expectException(SigningFailed::class);

        $this->key()->publicKey(SigningAlgorithm::RS256);
    }

    public function testASignatureByAnotherKeyIsNotUsed(): void
    {
        $this->vault->answeringKid = 'https://clavia-prod.vault.azure.net/keys/other/' . self::VERSION;

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('signed with a key other than');

        $_ = $this->key()->sign(hash('sha256', 'x', true), SigningAlgorithm::RS256);
    }
}
