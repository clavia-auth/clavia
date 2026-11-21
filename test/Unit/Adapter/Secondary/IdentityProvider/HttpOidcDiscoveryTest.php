<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\IdentityProvider;

use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Adapter\Secondary\IdentityProvider\HttpOidcDiscovery;
use Clavia\Application\Port\DiscoveryFailed;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\FakeOpenIdProvider;
use GuzzleHttp\Exception\ConnectException;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\HtmlResponse;
use Laminas\Diactoros\Response\JsonResponse;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Reading an issuer's discovery document: trusted for its endpoints only when it names
 * the issuer asked for, and only for endpoints the server may fetch.
 */
final class HttpOidcDiscoveryTest extends TestCase
{
    private FakeOpenIdProvider $idp;
    private FakeHttpClient $http;

    /** @var array<string, list<string>> What each host resolves to. */
    private array $dns = ['idp.example' => ['93.184.216.34'], 'internal.example' => ['10.0.0.5']];

    #[\Override]
    protected function setUp(): void
    {
        $this->idp = new FakeOpenIdProvider();
        $this->http = new FakeHttpClient($this->idp);
    }

    public function testTheEndpointsComeFromTheWellKnownDocument(): void
    {
        $provider = $this->discovery()->discover(FakeOpenIdProvider::ISSUER);

        self::assertSame(FakeOpenIdProvider::AUTHORIZATION_ENDPOINT, $provider->authorizationEndpoint);
        self::assertSame(FakeOpenIdProvider::TOKEN_ENDPOINT, $provider->tokenEndpoint);
        self::assertSame(FakeOpenIdProvider::JWKS_URI, $provider->jwksUri);
        self::assertSame(FakeOpenIdProvider::DISCOVERY_URL, (string) $this->http->requests[0]->getUri());
    }

    public function testADocumentNamingAnotherIssuerIsNotTrusted(): void
    {
        $this->idp->discoveryDocument = ['issuer' => 'https://evil.example'] + $this->idp->discovery();

        $this->expectExceptionObject(new DiscoveryFailed(
            'The discovery document at ' . FakeOpenIdProvider::DISCOVERY_URL
            . " does not name '" . FakeOpenIdProvider::ISSUER . "' as its issuer.",
        ));

        $this->discovery()->discover(FakeOpenIdProvider::ISSUER);
    }

    public function testAnEndpointAimedInsideTheNetworkIsRefused(): void
    {
        $this->idp->discoveryDocument = ['jwks_uri' => 'https://internal.example/keys'] + $this->idp->discovery();

        $this->expectExceptionObject(
            new DiscoveryFailed('The jwks_uri must not point at this server or an internal host.'),
        );

        $this->discovery()->discover(FakeOpenIdProvider::ISSUER);
    }

    public function testAnInternalIssuerIsNotEvenFetched(): void
    {
        try {
            $this->discovery()->discover('https://internal.example');
            self::fail('An internal issuer was fetched.');
        } catch (DiscoveryFailed) {
            self::assertSame([], $this->http->requests);
        }
    }

    public function testAMissingEndpointIsSaid(): void
    {
        $document = $this->idp->discovery();
        unset($document['token_endpoint']);
        $this->idp->discoveryDocument = $document;

        $this->expectExceptionObject(new DiscoveryFailed("The discovery document is missing 'token_endpoint'."));

        $this->discovery()->discover(FakeOpenIdProvider::ISSUER);
    }

    /**
     * @param callable(RequestInterface): ResponseInterface $answer
     */
    #[DataProvider('unusableAnswers')]
    public function testAnUnusableAnswerIsADiscoveryFailure(callable $answer, string $said): void
    {
        $this->http->answerWith($answer);

        try {
            $this->discovery()->discover(FakeOpenIdProvider::ISSUER);
            self::fail('An unusable answer was used.');
        } catch (DiscoveryFailed $failure) {
            self::assertStringContainsString($said, $failure->getMessage());
        }
    }

    /** @return iterable<string, array{callable(RequestInterface): ResponseInterface, string}> */
    public static function unusableAnswers(): iterable
    {
        yield 'unreachable' => [
            static fn (RequestInterface $request): never => throw new ConnectException('down', $request),
            'could not be reached',
        ];
        yield 'not found' => [static fn (): ResponseInterface => new JsonResponse([], 404), 'answered 404'];
        yield 'not JSON' => [static fn (): ResponseInterface => new HtmlResponse('<html>'), 'is not JSON'];
    }

    private function discovery(): HttpOidcDiscovery
    {
        return new HttpOidcDiscovery(
            $this->http,
            new RequestFactory(),
            new OutboundUrlPolicy(false, fn (string $host): array => $this->dns[$host] ?? []),
        );
    }
}
