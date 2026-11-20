<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Configuration\Settings;
use Laminas\Diactoros\ServerRequest;
use Laminas\ServiceManager\ServiceManager;
use Mezzio\Application;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;

/**
 * Drives the real application in-process: the same container, pipeline and routes as
 * `public/index.php`, with a request handed straight to the PSR-15 pipeline.
 *
 * This is where the tests ported from the Python project live. Each test gets a fresh
 * application, built from {@see self::ENVIRONMENT} plus whatever it overrides — never
 * from the machine's `.env`.
 */
abstract class AcceptanceTestCase extends TestCase
{
    /** @var array<string, string> */
    protected const array ENVIRONMENT = [
        'CLAVIA_ROOT_DOMAIN' => 'acme.com',
    ];

    protected RecordingLogger $logger;

    private ?ServiceManager $container = null;
    private ?Application $application = null;
    private int $errorReporting = E_ALL;

    #[\Override]
    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->container = null;
        $this->application = null;

        // The entry points report every PHP error, and the pipeline turns each into a
        // failure. PHPUnit narrows the level while a test runs; put it back so the
        // application behaves here as it does in production.
        $this->errorReporting = error_reporting(E_ALL);
    }

    #[\Override]
    protected function tearDown(): void
    {
        error_reporting($this->errorReporting);
    }

    /**
     * Start the application with different settings. Call before the first request.
     *
     * @param array<string, string> $environment `CLAVIA_*` variables laid over {@see self::ENVIRONMENT}.
     */
    protected function boot(array $environment = []): Application
    {
        /** @var ServiceManager $container */
        $container = require __DIR__ . '/../../config/container.php';
        $container->setAllowOverride(true);
        $container->setService(Settings::class, Settings::fromEnvironment($environment + self::ENVIRONMENT));
        $container->setService(LoggerInterface::class, $this->logger);

        /** @var Application $application */
        $application = $container->get(Application::class);
        (require __DIR__ . '/../../config/pipeline.php')($application);
        (require __DIR__ . '/../../config/routes.php')($application);

        $this->container = $container;

        return $this->application = $application;
    }

    protected function application(): Application
    {
        return $this->application ?? $this->boot();
    }

    protected function container(): ServiceManager
    {
        $this->application();
        assert($this->container !== null);

        return $this->container;
    }

    /**
     * @param array<non-empty-string, string> $headers
     */
    protected function request(
        string $method,
        string $path,
        array $headers = [],
        string $host = 'auth.acme.com',
    ): ResponseInterface {
        $request = new ServerRequest(
            serverParams: ['REMOTE_ADDR' => '203.0.113.7'],
            uri: 'https://' . $host . $path,
            method: $method,
            headers: $headers + ['Host' => $host],
        );

        return $this->application()->handle($request);
    }

    protected function get(string $path, string $host = 'auth.acme.com'): ResponseInterface
    {
        return $this->request('GET', $path, host: $host);
    }

    /**
     * @return array<array-key, mixed>
     */
    protected static function json(ResponseInterface $response): array
    {
        self::assertSame('application/json', $response->getHeaderLine('Content-Type'));

        /** @var array<array-key, mixed> */
        return json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
    }
}
