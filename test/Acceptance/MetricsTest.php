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
use ClaviaTest\Support\LoginFixtures;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Prometheus metrics (#23): what is measured, in the text exposition format, and only on the
 * internal listener.
 */
final class MetricsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use LoginFixtures;
    use MachineFixtures;

    public function testOnlyTheInternalListenerReadsTheMetrics(): void
    {
        $public = $this->get('/metrics');
        $forged = $this->request('GET', '/metrics', ['CLAVIA_LISTENER' => 'internal']);

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $public->getStatusCode());
        self::assertSame(
            StatusCodeInterface::STATUS_NOT_FOUND,
            $forged->getStatusCode(),
            'A header is no FastCGI parameter.',
        );
        $internal = $this->metrics();
        self::assertSame(StatusCodeInterface::STATUS_OK, $internal->getStatusCode());
        self::assertSame('text/plain; version=0.0.4; charset=utf-8', $internal->getHeaderLine('Content-Type'));
        self::assertSame('no-store', $internal->getHeaderLine('Cache-Control'));
        $counters = [
            'tokens_issued_total',
            'sign_ins_total',
            'sign_in_refusals_total',
            'oauth_errors_total',
            'mail_total',
        ];
        foreach ($counters as $name) {
            self::assertStringContainsString('# TYPE clavia_' . $name . " counter\n", (string) $internal->getBody());
        }
        $histogram = "# TYPE clavia_http_request_duration_seconds histogram\n";
        self::assertStringContainsString($histogram, (string) $internal->getBody());
    }

    public function testTokensSignInsAndRefusalsAreCountedByKindNeverByWho(): void
    {
        $this->user();
        $this->submitLogin(password: 'not the password');
        $this->clearCookies();
        $this->submitLogin();
        $this->post('/oauth2/token', [
            'grant_type' => 'client_credentials',
            'client_id' => 'nobody',
            'client_secret' => 'wrong',
        ]);

        $body = (string) $this->metrics()->getBody();

        self::assertStringContainsString('clavia_sign_ins_total{methods="pwd"} 1', $body);
        self::assertStringContainsString('clavia_oauth_errors_total{endpoint="token",error="invalid_client"} 1', $body);
        $refused = 'clavia_sign_in_refusals_total{reason="wrong_password",method="pwd"} 1';
        self::assertStringContainsString($refused, $body);
        self::assertStringNotContainsString(self::TEST_USER_EMAIL, $body);
        self::assertMatchesRegularExpression(
            '/clavia_http_request_duration_seconds_count\{route="oauth2.token",method="POST",status="401"\} 1/',
            $body,
        );
    }

    public function testOffNothingIsMeasuredAndNothingIsRead(): void
    {
        $this->boot(['CLAVIA_METRICS_ENABLED' => 'false']);
        $this->get('/.well-known/openid-configuration');

        self::assertSame(StatusCodeInterface::STATUS_NOT_FOUND, $this->metrics()->getStatusCode());
    }

    private function metrics(): ResponseInterface
    {
        return $this->request('GET', '/metrics', serverParams: ['CLAVIA_LISTENER' => 'internal']);
    }
}
