<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Configuration\Version;
use ClaviaTest\Support\AcceptanceTestCase;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LogLevel;
use RuntimeException;

/**
 * What every request gets, whichever surface it is for.
 */
final class PipelineTest extends AcceptanceTestCase
{
    public function testHealthzReportsTheProcessIsUp(): void
    {
        $response = $this->get('/healthz');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame(['status' => 'ok', 'version' => Version::CURRENT], self::json($response));
        self::assertSame('{"status":"ok","version":"' . Version::CURRENT . '"}', (string) $response->getBody());
    }

    public function testAnUnknownPathIsNotFound(): void
    {
        $response = $this->get('/nothing-here');

        self::assertSame(404, $response->getStatusCode());
        self::assertSame(['detail' => 'Not Found'], self::json($response));
    }

    public function testAKnownPathAnswersOnlyTheMethodsItDeclares(): void
    {
        $response = $this->request('POST', '/healthz');

        self::assertSame(405, $response->getStatusCode());
        self::assertSame('GET', $response->getHeaderLine('Allow'));
        self::assertSame(['detail' => 'Method Not Allowed'], self::json($response));
    }

    public function testHeadIsAnsweredWhereverGetIsWithoutABody(): void
    {
        $response = $this->request('HEAD', '/healthz');

        self::assertSame(200, $response->getStatusCode());
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));
        self::assertSame('', (string) $response->getBody());
    }

    public function testThereIsNoImplicitOptions(): void
    {
        self::assertSame(405, $this->request('OPTIONS', '/healthz')->getStatusCode());
    }

    public function testAnUncaughtErrorSaysNothingToTheClientAndEverythingToTheLog(): void
    {
        $this->application()->get(
            '/boom',
            static function (ServerRequestInterface $request): never {
                throw new RuntimeException('relation "signing_keys" does not exist');
            },
        );

        $response = $this->get('/boom');

        self::assertSame(500, $response->getStatusCode());
        self::assertSame('Internal Server Error', (string) $response->getBody());
        self::assertSame('text/plain; charset=utf-8', $response->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));

        self::assertCount(1, $this->logger->records);
        $record = $this->logger->records[0];
        self::assertSame(LogLevel::ERROR, $record['level']);
        self::assertSame('/boom', $record['context']['path'] ?? null);
        self::assertInstanceOf(RuntimeException::class, $record['context']['exception'] ?? null);
    }

    public function testAPhpWarningIsAnErrorNotSomethingToCarryOnFrom(): void
    {
        $this->application()->get('/warn', static function (ServerRequestInterface $request): never {
            trigger_error('half-built state', E_USER_WARNING);

            throw new RuntimeException('unreachable');
        });

        $response = $this->get('/warn');

        self::assertSame(500, $response->getStatusCode());
        self::assertSame('Internal Server Error', (string) $response->getBody());
        self::assertSame('half-built state', $this->logger->records[0]['context']['message'] ?? null);
    }
}
