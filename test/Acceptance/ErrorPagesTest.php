<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Http\Shared\PageRenderer;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\StatusCodeInterface;
use Mezzio\Template\TemplateRendererInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use RuntimeException;

/**
 * An error met in a browser is a page a person can read; the same error met by a program
 * is the JSON document (or plain text) it has always been. Same status, same headers.
 */
final class ErrorPagesTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;

    /** What a browser sends when it navigates to a page. */
    private const string BROWSER = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';

    // ── Not found ───────────────────────────────────────────────────────────────

    public function testABrowserMeetingAnUnknownAddressGetsAPage(): void
    {
        $response = $this->browse('GET', '/nothing-here');

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $response->getStatusCode());
        $this->assertIsAPage($response);
        self::assertStringContainsString('<h1>Page not found</h1>', (string) $response->getBody());
    }

    public function testAProgramMeetingAnUnknownAddressGetsJson(): void
    {
        $response = $this->request('GET', '/nothing-here', ['Accept' => '*/*']);

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $response->getStatusCode());
        self::assertSame(['detail' => 'Not Found'], self::json($response));
    }

    public function testTheMissingPathIsNotPrintedBack(): void
    {
        $response = $this->browse('GET', '/%3Cscript%3Ealert(1)%3C%2Fscript%3E');

        self::assertStringNotContainsString('script', (string) $response->getBody());
    }

    // ── Method not allowed ──────────────────────────────────────────────────────

    public function testABrowserUsingTheWrongMethodGetsAPageAndTheAllowedMethods(): void
    {
        $response = $this->browse('GET', '/auth/logout');

        self::assertSame(StatusCodeInterface::STATUS_METHOD_NOT_ALLOWED, $response->getStatusCode());
        self::assertSame('POST', $response->getHeaderLine('Allow'));
        $this->assertIsAPage($response);
        self::assertStringContainsString('This page cannot be opened this way', (string) $response->getBody());
    }

    public function testAProgramUsingTheWrongMethodGetsJsonAndTheAllowedMethods(): void
    {
        $response = $this->request('GET', '/oauth2/token');

        self::assertSame(StatusCodeInterface::STATUS_METHOD_NOT_ALLOWED, $response->getStatusCode());
        self::assertSame('POST', $response->getHeaderLine('Allow'));
        self::assertSame(['detail' => 'Method Not Allowed'], self::json($response));
    }

    // ── An authorization request that cannot be sent back ───────────────────────

    /**
     * RFC 6749 §4.1.2.1: when the client or its redirect URI cannot be trusted, the error
     * is shown to the person — and nothing on the page leads to the untrusted address.
     */
    public function testAnUntrustedAuthorizationRequestIsExplainedToThePerson(): void
    {
        $this->publicClient();
        [, $challenge] = $this->makePkcePair();

        $response = $this->browse('GET', '/oauth2/authorize?' . http_build_query($this->authorizeParams(
            $challenge,
            ['redirect_uri' => 'https://attacker.test/steal'],
        )));

        $body = (string) $response->getBody();
        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertFalse($response->hasHeader('Location'));
        self::assertFalse($response->hasHeader('WWW-Authenticate'));
        $this->assertIsAPage($response);
        self::assertStringContainsString('<h1>This sign-in cannot continue</h1>', $body);
        self::assertStringContainsString('invalid_request', $body);
        self::assertStringNotContainsString('attacker.test', $body);
        self::assertStringNotContainsString('<a ', $body);
        self::assertStringNotContainsString('<form', $body);
    }

    public function testAnUnknownClientIsExplainedToThePerson(): void
    {
        [, $challenge] = $this->makePkcePair();

        $response = $this->browse('GET', '/oauth2/authorize?' . http_build_query($this->authorizeParams(
            $challenge,
            ['client_id' => 'no-such-client'],
        )));

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        $this->assertIsAPage($response);
        self::assertStringContainsString('invalid_client', (string) $response->getBody());
    }

    public function testAProgramStillGetsTheOAuth2ErrorDocument(): void
    {
        [, $challenge] = $this->makePkcePair();

        $response = $this->get(
            '/oauth2/authorize',
            $this->authorizeParams($challenge, ['client_id' => 'no-such-client']),
        );

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('invalid_client', self::json($response)['error']);
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
    }

    public function testTheTokenEndpointAnswersJsonWhateverTheCallerAccepts(): void
    {
        // RFC 6749 §5.2 fixes the format: whoever calls it, it is a program.
        $response = $this->post('/oauth2/token', ['grant_type' => 'password'], headers: ['Accept' => self::BROWSER]);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('unsupported_grant_type', self::json($response)['error']);
    }

    // ── An uncaught error ───────────────────────────────────────────────────────

    public function testABrowserMeetingAFailureGetsAPageWithAReferenceAndNothingElse(): void
    {
        $this->failingRoute();

        $response = $this->browse('GET', '/boom');

        $body = (string) $response->getBody();
        $reference = $response->getHeaderLine('X-Error-Reference');
        self::assertSame(StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        $this->assertIsAPage($response);
        self::assertStringContainsString('<h1>Something went wrong</h1>', $body);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{12}$/D', $reference);
        self::assertStringContainsString($reference, $body);
        self::assertStringNotContainsString('signing_keys', $body);
        self::assertSame($reference, $this->logger->records[0]['context']['reference'] ?? null);
    }

    public function testAProgramMeetingAFailureGetsPlainTextAndTheReference(): void
    {
        $this->failingRoute();

        $response = $this->request('GET', '/boom', ['Accept' => 'application/json']);

        self::assertSame(StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        self::assertSame('Internal Server Error', (string) $response->getBody());
        self::assertSame(
            $this->logger->records[0]['context']['reference'] ?? null,
            $response->getHeaderLine('X-Error-Reference'),
        );
    }

    public function testWhenEvenTheErrorPageFailsThePlainAnswerIsSent(): void
    {
        $broken = new class implements TemplateRendererInterface {
            #[\Override]
            public function render(string $name, array|object $params = []): string
            {
                throw new RuntimeException('the template directory is gone');
            }

            #[\Override]
            public function addDefaultParam(string $templateName, string $param, mixed $value): void
            {
            }
        };
        $this->container()->setService(PageRenderer::class, new PageRenderer($broken));
        $this->failingRoute();

        $response = $this->browse('GET', '/boom');

        self::assertSame(StatusCodeInterface::STATUS_INTERNAL_SERVER_ERROR, $response->getStatusCode());
        self::assertSame('Internal Server Error', (string) $response->getBody());
        self::assertCount(2, $this->logger->records);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────

    private function browse(string $method, string $path): ResponseInterface
    {
        return $this->request($method, $path, ['Accept' => self::BROWSER]);
    }

    private function failingRoute(): void
    {
        $this->application()->get('/boom', static function (ServerRequestInterface $request): never {
            throw new RuntimeException('relation "signing_keys" does not exist');
        });
    }

    private function assertIsAPage(ResponseInterface $response): void
    {
        self::assertStringStartsWith('text/html', $response->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('DENY', $response->getHeaderLine('X-Frame-Options'));
        $policy = $response->getHeaderLine('Content-Security-Policy');
        self::assertStringContainsString("default-src 'none'", $policy);
        self::assertStringContainsString("form-action 'self';", $policy);
        self::assertStringNotContainsString('<script', (string) $response->getBody());
        // The page sets no cookie: an error is not a reason to start anything.
        self::assertFalse($response->hasHeader('Set-Cookie'));
    }
}
