<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Saml;

use Clavia\Adapter\Secondary\Saml\Remote\AzureKeyVaultDecryptionKey;
use Clavia\Adapter\Secondary\Saml\Remote\RemoteDecryptionKey;
use Clavia\Adapter\Secondary\Signing\Remote\Azure\AzureKeyVaultKey;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey;
use Clavia\Application\Port\DecryptionFailed;
use ClaviaTest\Support\Contract\ServiceProviderKeysContract;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\FakeKeyVault;
use ClaviaTest\Support\Fake\LocalHsm;
use ClaviaTest\Support\Fake\StaticAccessTokens;
use ClaviaTest\Support\RemoteServiceProviderKeysFixture;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/** The SAML keys in Azure Key Vault, over its mocked transport: two RSA keys, one that signs, one that decrypts. */
final class AzureKeyVaultServiceProviderKeysTest extends TestCase
{
    use ServiceProviderKeysContract;
    use RemoteServiceProviderKeysFixture;

    /** @var array<int, FakeKeyVault> */
    private array $vault = [];

    #[\Override]
    protected function remoteSigningKey(int $index): RemoteSigningKey
    {
        $this->vault($index, ['sign', 'verify']);

        return new AzureKeyVaultKey($this->api(), new StaticAccessTokens('azure-token'), self::url($index));
    }

    #[\Override]
    protected function remoteDecryptionKey(int $index): RemoteDecryptionKey
    {
        $this->vault($index, ['encrypt', 'decrypt']);

        return new AzureKeyVaultDecryptionKey($this->api(), new StaticAccessTokens('azure-token'), self::url($index));
    }

    public function testAKeyThatMayNotDecryptIsRefused(): void
    {
        $this->vault(1, ['sign']);
        $this->arrange();

        $this->expectException(DecryptionFailed::class);
        $this->serviceProviderKeys()->certificates();
    }

    /** @param list<string> $operations */
    private function vault(int $index, array $operations): void
    {
        if (! isset($this->vault[$index])) {
            $this->vault[$index] = new FakeKeyVault(self::url($index), new LocalHsm($index));
            $this->vault[$index]->operations = $operations;
        }
    }

    private function api(): JsonApi
    {
        $route = function (RequestInterface $request): ResponseInterface {
            $url = (string) $request->getUri()->withQuery('');
            foreach ($this->vault as $vault) {
                if ($url === $vault->keyUrl || str_starts_with($url, $vault->keyUrl . '/')) {
                    return $vault($request);
                }
            }

            return new JsonResponse(['error' => ['code' => 'KeyNotFound']], StatusCodeInterface::STATUS_NOT_FOUND);
        };

        return new JsonApi(new FakeHttpClient($route), new RequestFactory(), new StreamFactory(), 'Azure Key Vault');
    }

    private static function url(int $index): string
    {
        return 'https://clavia-prod.vault.azure.net/keys/saml-' . $index . '/' . str_repeat((string) $index, 32);
    }
}
