<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Secondary\Crypto\BcryptPasswordHasher;
use Clavia\Adapter\Secondary\System\AfterResponseTasks;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Configuration\Settings;
use Clavia\Domain\Shared\Clock;
use ClaviaTest\Support\Fake\FrozenClock;
use Laminas\Diactoros\ServerRequest;
use Laminas\Diactoros\Stream;
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
 * application, built from {@see TestEnvironment::variables()} plus whatever it
 * overrides — never from the machine's `.env` — and starts with every table and the
 * Redis test database empty.
 */
abstract class AcceptanceTestCase extends TestCase
{
    /** The origin every request is sent to unless a test says otherwise. */
    protected const string AUTH_HOST = 'auth.' . TestEnvironment::ROOT_DOMAIN;

    protected const string MANAGEMENT_HOST = 'management.' . TestEnvironment::ROOT_DOMAIN;

    protected RecordingLogger $logger;

    private ?ServiceManager $container = null;
    private ?Application $application = null;
    private int $errorReporting = E_ALL;

    /**
     * The browser's cookie jar: what the server set, sent back on every later request
     * whose path matches, as a browser would. One host, so no domain matching.
     *
     * @var array<string, array{name: string, value: string, path: string}> Keyed by name and path.
     */
    private array $cookieJar = [];

    #[\Override]
    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->container = null;
        $this->application = null;
        $this->cookieJar = [];

        // The entry points report every PHP error, and the pipeline turns each into a
        // failure. PHPUnit narrows the level while a test runs; put it back so the
        // application behaves here as it does in production.
        $this->errorReporting = error_reporting(E_ALL);

        TestStorage::reset();
        // An authorization request asks for `openid` unless a test says otherwise, so the
        // token endpoint needs a key to sign ID tokens with. A test about having none
        // deletes it.
        TestSigningKeys::install(TestStorage::database());
    }

    #[\Override]
    protected function tearDown(): void
    {
        error_reporting($this->errorReporting);

        // PHPUnit keeps every finished test object until the run ends; a container left
        // on one keeps its PostgreSQL connection open, and a long suite runs out of them.
        $this->application = null;
        $this->container = null;
        gc_collect_cycles();
    }

    /**
     * Start the application with different settings. Call before the first request.
     *
     * @param array<string, string> $environment `CLAVIA_*` variables laid over the test environment.
     */
    protected function boot(array $environment = []): Application
    {
        /** @var ServiceManager $container */
        $container = require __DIR__ . '/../../config/container.php';
        $container->setAllowOverride(true);
        $container->setService(Settings::class, Settings::fromEnvironment($environment + TestEnvironment::variables()));
        $container->setService(LoggerInterface::class, $this->logger);
        // The real adapter at bcrypt's lowest cost: the suite is about behaviour, and
        // the production cost would spend most of its time hashing fixtures.
        $container->setService(PasswordHasher::class, new BcryptPasswordHasher(4));

        /** @var Application $application */
        $application = $container->get(Application::class);
        (require __DIR__ . '/../../config/pipeline.php')($application);
        (require __DIR__ . '/../../config/routes.php')($application);

        $this->container = $container;

        return $this->application = $application;
    }

    /**
     * Stop the application's clock, so a test can move time instead of waiting for it.
     * Call before the first request: services read the clock they were built with.
     */
    protected function freezeClock(string $at = '2026-01-15T10:00:00Z'): FrozenClock
    {
        $clock = new FrozenClock($at);
        $this->container()->setService(Clock::class, $clock);

        return $clock;
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
        string $host = self::AUTH_HOST,
        string $body = '',
    ): ResponseInterface {
        $stream = new Stream('php://temp', 'wb+');
        $stream->write($body);
        $stream->rewind();

        // A Cookie header given by the test replaces the jar for that request.
        $cookies = $this->cookiesFor((string) parse_url($path, PHP_URL_PATH));
        if (! array_key_exists('Cookie', $headers) && $cookies !== '') {
            $headers['Cookie'] = $cookies;
        }

        $request = new ServerRequest(
            serverParams: ['REMOTE_ADDR' => '203.0.113.7'],
            uri: 'https://' . $host . $path,
            method: $method,
            body: $stream,
            headers: $headers + ['Host' => $host],
        );

        $response = $this->application()->handle($request);
        $this->remember($response);
        // As the entry point does once the response is out.
        $this->container()->get(AfterResponseTasks::class)->run();

        return $response;
    }

    /**
     * The value the browser holds for a cookie — at its most specific path.
     */
    protected function cookie(string $name, ?string $path = null): ?string
    {
        foreach ($this->jarInSendingOrder() as $cookie) {
            if ($cookie['name'] === $name && ($path === null || $cookie['path'] === $path)) {
                return $cookie['value'];
            }
        }

        return null;
    }

    /** Plant a cookie in the browser, as an attacker or an earlier version of the server might. */
    protected function setCookie(string $name, string $value, string $path = '/'): void
    {
        $this->cookieJar[$name . '|' . $path] = ['name' => $name, 'value' => $value, 'path' => $path];
    }

    protected function clearCookies(): void
    {
        $this->cookieJar = [];
    }

    /**
     * The raw `Set-Cookie` header a response carries for `$name`, so its attributes can
     * be asserted; the first one when there are several.
     */
    protected static function setCookieHeader(ResponseInterface $response, string $name): ?string
    {
        return self::setCookieHeaders($response, $name)[0] ?? null;
    }

    /**
     * @return list<string>
     */
    protected static function setCookieHeaders(ResponseInterface $response, string $name): array
    {
        return array_values(array_filter(
            $response->getHeader('Set-Cookie'),
            static fn (string $header): bool => str_starts_with($header, $name . '='),
        ));
    }

    /** Store what a response set, and drop what it expired (RFC 6265 §5.3). */
    private function remember(ResponseInterface $response): void
    {
        foreach ($response->getHeader('Set-Cookie') as $header) {
            $parts = array_map(trim(...), explode(';', $header));
            [$name, $value] = explode('=', $parts[0], 2) + [1 => ''];
            $parts = array_slice($parts, 1);
            $path = '/';
            $expired = false;

            foreach ($parts as $attribute) {
                [$key, $argument] = explode('=', $attribute, 2) + [1 => ''];
                match (strtolower($key)) {
                    'path' => $path = $argument,
                    'max-age' => $expired = (int) $argument <= 0,
                    default => null,
                };
            }

            if ($expired) {
                unset($this->cookieJar[$name . '|' . $path]);
            } else {
                $this->setCookie($name, $value, $path);
            }
        }
    }

    /** The `Cookie` header a browser would send to this path, most specific path first. */
    private function cookiesFor(string $requestPath): string
    {
        $pairs = [];
        foreach ($this->jarInSendingOrder() as $cookie) {
            if (self::pathMatches($requestPath === '' ? '/' : $requestPath, $cookie['path'])) {
                $pairs[] = $cookie['name'] . '=' . $cookie['value'];
            }
        }

        return implode('; ', $pairs);
    }

    /**
     * @return list<array{name: string, value: string, path: string}>
     */
    private function jarInSendingOrder(): array
    {
        $cookies = array_values($this->cookieJar);
        usort($cookies, static fn (array $a, array $b): int => strlen($b['path']) <=> strlen($a['path']));

        return $cookies;
    }

    /** RFC 6265 §5.1.4. */
    private static function pathMatches(string $requestPath, string $cookiePath): bool
    {
        return $requestPath === $cookiePath
            || (str_starts_with($requestPath, $cookiePath)
                && (str_ends_with($cookiePath, '/') || ($requestPath[strlen($cookiePath)] ?? '') === '/'));
    }

    /**
     * @param array<string, string> $query
     */
    protected function get(string $path, array $query = [], string $host = self::AUTH_HOST): ResponseInterface
    {
        $queryString = http_build_query($query, '', '&', PHP_QUERY_RFC3986);

        return $this->request('GET', $path . ($queryString === '' ? '' : '?' . $queryString), host: $host);
    }

    /**
     * Post a form, as a browser or an OAuth client library would.
     *
     * @param array<string, string>                  $form
     * @param array{0: string, 1: string}|null       $basicAuth Client id and secret for HTTP Basic.
     * @param array<non-empty-string, string>        $headers
     */
    protected function post(
        string $path,
        array $form = [],
        ?array $basicAuth = null,
        array $headers = [],
        string $host = self::AUTH_HOST,
    ): ResponseInterface {
        $headers += ['Content-Type' => 'application/x-www-form-urlencoded'];
        if ($basicAuth !== null) {
            $headers['Authorization'] = 'Basic ' . base64_encode($basicAuth[0] . ':' . $basicAuth[1]);
        }

        return $this->request('POST', $path, $headers, $host, http_build_query($form, '', '&', PHP_QUERY_RFC3986));
    }

    /**
     * The query parameters of a redirect's `Location`.
     *
     * @return array<string, string>
     */
    protected static function locationQuery(ResponseInterface $response): array
    {
        parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $query);

        /** @var array<string, string> $query */
        return $query;
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
