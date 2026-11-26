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
use ClaviaTest\Support\DpopClient;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * DPoP at this server's own protected resources (RFC 9449 §7; docs/design/dpop.md, slice 3):
 * userinfo and the Management API take a bound token with the `DPoP` scheme and a fresh proof
 * naming it, refuse it as `Bearer`, and answer a DPoP request with a `DPoP` challenge.
 */
final class DpopResourcesTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string USERS = 'https://management.clavia.test/api/v1/users';
    private const string USERINFO = 'https://auth.clavia.test/oidc/userinfo';
    private const string TOKEN = 'https://auth.clavia.test/oauth2/token';
    private const string ALGS = 'algs="ES256 EdDSA RS256"';

    // ── The Management API ──────────────────────────────────────────────────────

    public function testABoundTokenWorksWithAProofFromItsKey(): void
    {
        $client = DpopClient::es256();
        $token = $this->boundAdminToken($client);

        $response = $this->management(
            $token,
            $client->proof(RequestMethodInterface::METHOD_GET, self::USERS, accessToken: $token),
        );

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
    }

    public function testABoundTokenIsUselessAsABearerToken(): void
    {
        // RFC 9449 §7.2: otherwise binding would be optional for whoever stole it.
        $token = $this->boundAdminToken(DpopClient::es256());

        $response = $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/users', token: $token);

        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
        self::assertSame('invalid_token', self::json($response)['error']);
    }

    public function testWithoutAProofOrWithAnotherKeysItIsRefusedInTheDpopScheme(): void
    {
        $client = DpopClient::es256();
        $token = $this->boundAdminToken($client);

        $noProof = $this->management($token, null);
        $anotherKey = $this->management(
            $token,
            DpopClient::es256()->proof(RequestMethodInterface::METHOD_GET, self::USERS, accessToken: $token),
        );
        $anotherUrl = $this->management(
            $token,
            $client->proof(RequestMethodInterface::METHOD_GET, self::USERINFO, accessToken: $token),
        );
        $anotherToken = $this->management(
            $token,
            $client->proof(RequestMethodInterface::METHOD_GET, self::USERS, accessToken: 'another'),
        );

        foreach ([$noProof, $anotherKey, $anotherUrl, $anotherToken] as $response) {
            self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $response->getStatusCode());
            self::assertSame('invalid_dpop_proof', self::json($response)['error']);
            self::assertStringStartsWith('DPoP ', $response->getHeaderLine('WWW-Authenticate'));
            self::assertStringContainsString(self::ALGS, $response->getHeaderLine('WWW-Authenticate'));
        }
    }

    public function testAProofIsGoodForOneRequest(): void
    {
        $client = DpopClient::es256();
        $token = $this->boundAdminToken($client);
        $proof = $client->proof(RequestMethodInterface::METHOD_GET, self::USERS, accessToken: $token);

        self::assertSame(StatusCodeInterface::STATUS_OK, $this->management($token, $proof)->getStatusCode());
        self::assertSame('invalid_dpop_proof', self::json($this->management($token, $proof))['error']);
    }

    public function testABearerTokenIsNotADpopOne(): void
    {
        $token = $this->adminToken();

        $response = $this->management(
            $token,
            DpopClient::es256()->proof(RequestMethodInterface::METHOD_GET, self::USERS, accessToken: $token),
        );

        self::assertSame('invalid_token', self::json($response)['error']);
        self::assertStringStartsWith('DPoP ', $response->getHeaderLine('WWW-Authenticate'));
    }

    // ── Userinfo ────────────────────────────────────────────────────────────────

    public function testUserinfoTakesABoundTokenWithItsProofOnly(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $client = DpopClient::es256();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['scope' => 'openid email']);
        $token = self::json($this->withNonce($client, fn (string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: ['DPoP' => $proof],
        )))['access_token'];
        self::assertIsString($token);

        $withProof = $this->request(RequestMethodInterface::METHOD_GET, '/oidc/userinfo', [
            'Authorization' => 'DPoP ' . $token,
            'DPoP' => $client->proof(RequestMethodInterface::METHOD_GET, self::USERINFO, accessToken: $token),
        ]);
        $asBearer = $this->request(
            RequestMethodInterface::METHOD_GET,
            '/oidc/userinfo',
            ['Authorization' => 'Bearer ' . $token],
        );

        self::assertSame(StatusCodeInterface::STATUS_OK, $withProof->getStatusCode(), (string) $withProof->getBody());
        self::assertSame(self::TEST_USER_EMAIL, self::json($withProof)['email']);
        self::assertSame(StatusCodeInterface::STATUS_UNAUTHORIZED, $asBearer->getStatusCode());
    }

    /** A Management API token for the machine client, bound to `$client`'s key. */
    private function boundAdminToken(DpopClient $client): string
    {
        $this->adminToken();
        $token = self::json($this->withNonce($client, fn (string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            ['grant_type' => 'client_credentials', 'audience' => self::MANAGEMENT_API],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
            headers: ['DPoP' => $proof],
        )))['access_token'];
        self::assertIsString($token);

        return $token;
    }

    private function management(string $token, ?string $proof): ResponseInterface
    {
        $headers = ['Authorization' => 'DPoP ' . $token];
        if ($proof !== null) {
            $headers['DPoP'] = $proof;
        }

        return $this->api(RequestMethodInterface::METHOD_GET, '/api/v1/users', token: '', headers: $headers);
    }

    /** @param callable(string): ResponseInterface $send */
    private function withNonce(DpopClient $client, callable $send): ResponseInterface
    {
        $first = $send($client->proof(RequestMethodInterface::METHOD_POST, self::TOKEN));
        if ((self::json($first)['error'] ?? null) !== 'use_dpop_nonce') {
            return $first;
        }

        return $send(
            $client->proof(RequestMethodInterface::METHOD_POST, self::TOKEN, $first->getHeaderLine('DPoP-Nonce')),
        );
    }
}
