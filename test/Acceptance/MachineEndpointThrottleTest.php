<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Failures at the endpoints machines call — token, introspection, revocation, device
 * authorization — are limited per client address, and per client that proved itself with a
 * secret (`CLAVIA_TOKEN_MAX_FAILURES` per `CLAVIA_TOKEN_FAILURE_WINDOW`). Past the limit the
 * endpoint answers `429` with `Retry-After` (RFC 6585 §4) before checking anything.
 * Successes never count.
 */
final class MachineEndpointThrottleTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;

    private const string ATTACKER = '198.51.100.9';

    private const string NEIGHBOUR = '192.0.2.44';

    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();
        $this->boot(['CLAVIA_TOKEN_MAX_FAILURES' => '3', 'CLAVIA_TOKEN_FAILURE_WINDOW' => '300']);
    }

    public function testWrongSecretsFromOneAddressAreRefusedThereAndNowhereElse(): void
    {
        $this->machineApi();
        $this->comeFrom(self::ATTACKER);
        for ($i = 0; $i < 3; ++$i) {
            $wrong = $this->requestMachineToken(credentials: [self::TEST_M2M_CLIENT_ID, 'wrong']);
            self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $wrong->getStatusCode());
        }

        // Even the right secret: the address is refused before any secret is checked.
        self::assertTooManyFailures($this->requestMachineToken());

        // The client itself is not locked out: its id is not a secret.
        $this->comeFrom(self::NEIGHBOUR);
        self::assertSame(StatusCodeInterface::STATUS_OK, $this->requestMachineToken()->getStatusCode());
    }

    public function testAWellBehavedClientIsNeverRefused(): void
    {
        $this->machineApi();

        for ($i = 0; $i < 10; ++$i) {
            self::assertSame(StatusCodeInterface::STATUS_OK, $this->requestMachineToken()->getStatusCode());
        }
    }

    public function testRejectedGrantsRefuseAProvenClientFromEveryAddress(): void
    {
        // A confidential client presenting codes that do not exist is misbehaving, whoever runs it.
        $this->confidentialClient();
        $this->comeFrom(self::ATTACKER);
        for ($i = 0; $i < 3; ++$i) {
            self::assertSame('invalid_grant', self::json($this->redeemAsConfidential('no-such-code'))['error']);
        }

        $this->comeFrom(self::NEIGHBOUR);

        self::assertTooManyFailures($this->redeemAsConfidential('no-such-code'));
    }

    public function testNobodyCanLockAPublicClientOutByNamingIt(): void
    {
        $this->publicClient();
        $this->comeFrom(self::ATTACKER);
        for ($i = 0; $i < 3; ++$i) {
            $this->post('/oauth2/token', $this->tokenRequest('no-such-code', 'a-verifier'));
        }
        self::assertTooManyFailures($this->post('/oauth2/token', $this->tokenRequest('no-such-code', 'a-verifier')));

        // Another person's browser, with a real code, is not refused.
        $this->comeFrom(self::NEIGHBOUR);
        $this->loggedIn();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        self::assertSame(
            StatusCodeInterface::STATUS_OK,
            $this->post('/oauth2/token', $this->tokenRequest($code, $verifier))->getStatusCode(),
        );
    }

    public function testIntrospectionRevocationAndDeviceAuthorizationCountFailedAuthentication(): void
    {
        $this->machineApi();
        $this->comeFrom(self::ATTACKER);
        $wrong = [self::TEST_M2M_CLIENT_ID, 'wrong'];
        $this->post('/oauth2/introspect', ['token' => 'x'], basicAuth: $wrong);
        $this->post('/oauth2/revoke', ['token' => 'x'], basicAuth: $wrong);
        $this->post('/oauth2/device/code', ['scope' => 'openid'], basicAuth: $wrong);

        foreach (['/oauth2/introspect', '/oauth2/revoke', '/oauth2/device/code'] as $endpoint) {
            self::assertTooManyFailures(
                $this->post($endpoint, ['token' => 'x'], basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET]),
            );
        }
        // One counter for all four: the token endpoint refuses this address too.
        self::assertTooManyFailures($this->requestMachineToken());
    }

    public function testAnInactiveTokenAtIntrospectionIsNoFailure(): void
    {
        // A resource server introspecting expired tokens is doing its job.
        $this->machineApi();

        for ($i = 0; $i < 5; ++$i) {
            $answer = $this->post(
                '/oauth2/introspect',
                ['token' => 'expired-or-unknown'],
                basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
            );
            self::assertSame(['active' => false], self::json($answer));
        }
    }

    private function redeemAsConfidential(string $code): ResponseInterface
    {
        // The fixture authenticates with `client_secret_post`.
        return $this->post('/oauth2/token', [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => self::TEST_REDIRECT_URI,
            'client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID,
            'client_secret' => self::TEST_CLIENT_SECRET,
        ]);
    }

    private static function assertTooManyFailures(ResponseInterface $response): void
    {
        self::assertSame(
            StatusCodeInterface::STATUS_TOO_MANY_REQUESTS,
            $response->getStatusCode(),
            (string) $response->getBody(),
        );
        self::assertSame('300', $response->getHeaderLine('Retry-After'));
        self::assertSame('no-store', $response->getHeaderLine('Cache-Control'));
        self::assertSame('temporarily_unavailable', self::json($response)['error']);
    }
}
