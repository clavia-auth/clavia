<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Signing\Remote;

use Clavia\Adapter\Secondary\Signing\Remote\Azure\EntraApplication;
use Clavia\Adapter\Secondary\Signing\Remote\Azure\ManagedIdentity;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Application\Port\SigningFailed;
use ClaviaTest\Support\Fake\FakeHttpClient;
use ClaviaTest\Support\Fake\FrozenClock;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\Response\JsonResponse;
use Laminas\Diactoros\StreamFactory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

final class AzureCredentialsTest extends TestCase
{
    private const string SCOPE = 'https://vault.azure.net/.default';

    private FakeHttpClient $http;

    private FrozenClock $clock;

    private int $issued = 0;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->http = new FakeHttpClient(function (): JsonResponse {
            $this->issued++;

            // Managed identity endpoints send `expires_on`, a Unix time, as a string.
            return new JsonResponse([
                'access_token' => 'token-' . $this->issued,
                'expires_on' => (string) ($this->clock->now()->getTimestamp() + 3600),
                'resource' => 'https://vault.azure.net',
            ]);
        });
    }

    public function testTheInstanceMetadataServiceIsAskedForTheVaultResource(): void
    {
        $tokens = new ManagedIdentity($this->api(), $this->clock, self::SCOPE);

        self::assertSame('token-1', $tokens->token());

        $request = $this->http->requests[0] ?? null;
        self::assertNotNull($request);
        self::assertSame(
            ManagedIdentity::INSTANCE_METADATA . '?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net',
            (string) $request->getUri(),
        );
        self::assertSame('true', $request->getHeaderLine('Metadata'));
    }

    public function testAUserAssignedIdentityIsChosenByItsClientId(): void
    {
        $tokens = new ManagedIdentity($this->api(), $this->clock, self::SCOPE, 'f2b1c3d4');

        $_ = $tokens->token();

        self::assertStringEndsWith('&client_id=f2b1c3d4', (string) ($this->http->requests[0] ?? null)?->getUri());
    }

    public function testAppServiceAnswersAtTheEndpointItAnnounces(): void
    {
        $tokens = new ManagedIdentity(
            $this->api(),
            $this->clock,
            self::SCOPE,
            null,
            'http://localhost:42356/msi/token',
            'header-secret',
        );

        $_ = $tokens->token();

        $request = $this->http->requests[0] ?? null;
        self::assertNotNull($request);
        self::assertStringStartsWith(
            'http://localhost:42356/msi/token?api-version=2019-08-01&',
            (string) $request->getUri(),
        );
        self::assertSame('header-secret', $request->getHeaderLine('X-IDENTITY-HEADER'));
    }

    public function testATokenIsKeptUntilAMinuteBeforeItExpires(): void
    {
        $tokens = new ManagedIdentity($this->api(), $this->clock, self::SCOPE);

        self::assertSame('token-1', $tokens->token());
        $this->clock->advance(3539);
        self::assertSame('token-1', $tokens->token());
        $this->clock->advance(1);
        self::assertSame('token-2', $tokens->token());
    }

    public function testAnApplicationSignsInWithItsSecret(): void
    {
        $this->http->answerWith(self::issuing(3599));
        $tokens = $this->application('s3cret');

        self::assertSame('app', $tokens->token());

        $request = $this->http->requests[0] ?? null;
        self::assertNotNull($request);
        self::assertSame('https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token', (string) $request->getUri());
        self::assertSame(
            [
                'grant_type' => 'client_credentials',
                'client_id' => 'client-1',
                'scope' => self::SCOPE,
                'client_secret' => 's3cret',
            ],
            FakeHttpClient::form($request),
        );
    }

    public function testWorkloadIdentityPresentsTheProjectedTokenAsItIsNow(): void
    {
        // Expiring at once: every token() asks again.
        $this->http->answerWith(self::issuing(1));
        $file = tempnam(sys_get_temp_dir(), 'azure-token');
        self::assertIsString($file);
        $tokens = EntraApplication::withFederatedToken(
            $this->api(),
            $this->clock,
            self::SCOPE,
            'tenant-1',
            'client-1',
            $file,
        );

        file_put_contents($file, "projected.jwt.one\n");
        $_ = $tokens->token();
        file_put_contents($file, 'projected.jwt.two');
        $_ = $tokens->token();
        unlink($file);

        $forms = array_map(FakeHttpClient::form(...), $this->http->requests);
        [$first, $second] = [$forms[0] ?? [], $forms[1] ?? []];
        self::assertSame('projected.jwt.one', $first['client_assertion'] ?? null);
        self::assertSame(
            'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            $first['client_assertion_type'] ?? null,
        );
        self::assertArrayNotHasKey('client_secret', $first);
        self::assertSame('projected.jwt.two', $second['client_assertion'] ?? null);

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('cannot be read');
        $_ = $tokens->token();
    }

    public function testARefusedSignInSaysWhy(): void
    {
        $this->http->answerWith(static fn (RequestInterface $request): JsonResponse => new JsonResponse(
            ['error' => 'invalid_client', 'error_description' => 'AADSTS7000215: Invalid client secret provided.'],
            401,
        ));
        $tokens = $this->application('wrong');

        $this->expectException(SigningFailed::class);
        $this->expectExceptionMessageIsOrContains('Microsoft Entra ID refused the request (HTTP 401): AADSTS7000215');

        $_ = $tokens->token();
    }

    private function application(string $secret): EntraApplication
    {
        return EntraApplication::withSecret($this->api(), $this->clock, self::SCOPE, 'tenant-1', 'client-1', $secret);
    }

    /**
     * @return callable(RequestInterface): JsonResponse
     */
    private static function issuing(int $lifetime): callable
    {
        return static fn (RequestInterface $request): JsonResponse => new JsonResponse(
            ['access_token' => 'app', 'expires_in' => $lifetime],
        );
    }

    private function api(): JsonApi
    {
        return new JsonApi($this->http, new RequestFactory(), new StreamFactory(), 'Microsoft Entra ID');
    }
}
