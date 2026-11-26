<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\BreachedPasswords;

use Clavia\Adapter\Secondary\BreachedPasswords\NoBreachedPasswords;
use Clavia\Adapter\Secondary\BreachedPasswords\PwnedPasswordsRange;
use Clavia\Adapter\Secondary\Http\OutboundUrlPolicy;
use Clavia\Application\Port\BreachCheckUnavailable;
use Clavia\Application\Port\BreachedPasswords;
use ClaviaTest\Support\Contract\BreachedPasswordsContract;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\PwnedPasswordsService;
use ClaviaTest\Support\RecordingLogger;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use GuzzleHttp\Exception\ConnectException;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\TextResponse;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The Pwned Passwords range API, by k-anonymity
 * (https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange), against a fake of the
 * service that answers as it does: every suffix under the prefix, padded.
 */
final class PwnedPasswordsRangeTest extends BreachedPasswordsContract
{
    private FakeHttpClient $http;
    private RecordingLogger $logger;

    #[\Override]
    protected function setUp(): void
    {
        $this->http = new FakeHttpClient();
        $this->logger = new RecordingLogger();
    }

    #[\Override]
    protected function corpus(array $breached): BreachedPasswords
    {
        $this->http->answerWith(PwnedPasswordsService::knowing($breached));

        return $this->adapter();
    }

    #[\Override]
    protected function unavailableCorpus(): BreachedPasswords
    {
        $this->http->answerWith(
            static fn (): ResponseInterface => new TextResponse('', StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE),
        );

        return $this->adapter();
    }

    public function testOnlyTheFirstFiveCharactersOfTheHashLeave(): void
    {
        $_ = $this->corpus([])->isBreached('password123');

        self::assertCount(1, $this->http->requests);
        $request = $this->http->requests[0];
        $hash = PwnedPasswordsRange::hashOf('password123');
        self::assertSame(RequestMethodInterface::METHOD_GET, $request->getMethod());
        self::assertSame('https://api.pwnedpasswords.com/range/' . substr($hash, 0, 5), (string) $request->getUri());
        self::assertSame('true', $request->getHeaderLine('Add-Padding'));
        self::assertStringNotContainsString(substr($hash, 5), self::wire($request));
        self::assertStringNotContainsString('password123', self::wire($request));
    }

    public function testTheKeyIsTheUpperCaseSha1(): void
    {
        // The service's own example: "password" is under 5BAA6.
        self::assertSame('5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8', PwnedPasswordsRange::hashOf('password'));
    }

    public function testAPaddingEntryIsNoBreach(): void
    {
        // The service pads with suffixes it has never seen, counted 0.
        $suffix = substr(PwnedPasswordsRange::hashOf('password123'), 5);
        $this->http->answerWith(static fn (): ResponseInterface => new TextResponse($suffix . ":0\r\n"));

        self::assertFalse($this->adapter()->isBreached('password123'));
    }

    public function testAFailureIsLoggedWithoutThePassword(): void
    {
        try {
            $_ = $this->unavailableCorpus()->isBreached('password123');
            self::fail('An unavailable service is reported.');
        } catch (BreachCheckUnavailable) {
        }

        self::assertTrue($this->logger->hasRecordContaining('answered 503'));
        self::assertFalse($this->logger->hasRecordContaining(substr(PwnedPasswordsRange::hashOf('password123'), 0, 5)));
        self::assertFalse($this->logger->hasRecordContaining('password123'));
    }

    public function testAnUnreachableServiceIsUnavailable(): void
    {
        $this->http->answerWith(static function (RequestInterface $request): ResponseInterface {
            throw new ConnectException('Connection refused', $request);
        });

        $this->expectException(BreachCheckUnavailable::class);

        $_ = $this->adapter()->isBreached('password123');
    }

    public function testTheOutboundPolicyApplies(): void
    {
        // A resolver steered at the private network: nothing is sent.
        $adapter = $this->adapter(['10.0.0.5']);

        try {
            $_ = $adapter->isBreached('password123');
            self::fail('A refused address is reported.');
        } catch (BreachCheckUnavailable) {
        }

        self::assertSame([], $this->http->requests);
        self::assertTrue($this->logger->hasRecordContaining('must not point at this server'));
    }

    public function testWithTheCheckOffNothingIsBreachedAndNothingSent(): void
    {
        self::assertFalse(new NoBreachedPasswords()->isBreached('password123'));
    }

    /**
     * @param list<string> $addresses What every name resolves to.
     */
    private function adapter(array $addresses = ['104.16.0.1']): PwnedPasswordsRange
    {
        return new PwnedPasswordsRange(
            $this->http,
            new RequestFactory(),
            new OutboundUrlPolicy(false, static fn (): array => $addresses),
            $this->logger,
        );
    }

    /** Everything the request carries: target, headers and body. */
    private static function wire(RequestInterface $request): string
    {
        $wire = (string) $request->getUri() . "\n";
        foreach ($request->getHeaders() as $name => $values) {
            $wire .= $name . ': ' . implode(', ', $values) . "\n";
        }

        return $wire . (string) $request->getBody();
    }
}
