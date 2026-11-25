<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Saml;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\Saml\HttpSamlMetadataSource;
use Clavia\Adapter\Secondary\Saml\SimpleSamlServiceProvider;
use Clavia\Application\Port\Saml\MetadataUnavailable;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Fake\FakeHttpClient;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\TextResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;

/** An identity provider's metadata over HTTPS: the policy first, a 200 only, bounded (§5.2). */
final class HttpSamlMetadataSourceTest extends TestCase
{
    public function testTheDocumentIsFetched(): void
    {
        $http = new FakeHttpClient(static fn (): ResponseInterface => new TextResponse('<EntityDescriptor/>'));

        $fetched = self::source($http)->fetch(Url::fromString('https://idp.example/metadata'));

        self::assertSame('<EntityDescriptor/>', $fetched);
        self::assertStringContainsString('samlmetadata+xml', $http->requests[0]->getHeaderLine('Accept'));
    }

    public function testAPrivateAddressIsNeverFetched(): void
    {
        $http = new FakeHttpClient(static fn (): ResponseInterface => new TextResponse('<EntityDescriptor/>'));
        $source = new HttpSamlMetadataSource(
            $http,
            new RequestFactory(),
            new OutboundUrlPolicy(false, static fn (): array => ['10.0.0.7']),
        );

        try {
            $source->fetch(Url::fromString('https://idp.example/metadata'));
            self::fail('Fetched.');
        } catch (MetadataUnavailable) {
            self::assertSame([], $http->requests);
        }
    }

    public function testAnythingButA200OrAnOversizedDocumentIsUnavailable(): void
    {
        foreach (
            [
                new TextResponse('gone', StatusCodeInterface::STATUS_NOT_FOUND),
                new TextResponse('moved', StatusCodeInterface::STATUS_FOUND),
                new TextResponse(str_repeat('x', SimpleSamlServiceProvider::MAX_METADATA_BYTES + 1)),
            ] as $response
        ) {
            try {
                self::source(new FakeHttpClient(static fn (): ResponseInterface => $response))
                    ->fetch(Url::fromString('https://idp.example/metadata'));
                self::fail('Accepted.');
            } catch (MetadataUnavailable $refused) {
                self::assertNotSame('', $refused->getMessage());
            }
        }
    }

    private static function source(FakeHttpClient $http): HttpSamlMetadataSource
    {
        return new HttpSamlMetadataSource(
            $http,
            new RequestFactory(),
            new OutboundUrlPolicy(false, static fn (): array => ['93.184.216.34']),
        );
    }
}
