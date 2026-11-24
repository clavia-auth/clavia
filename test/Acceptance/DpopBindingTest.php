<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Client\GrantType;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\DpopClient;
use ClaviaTest\Support\OAuth2Fixtures;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * DPoP-bound codes and refresh tokens (RFC 9449 §10, §5; docs/design/dpop.md, slice 2): a code
 * bound with `dpop_jkt` — or through a pushed request carrying a proof — is redeemed with that
 * key or not at all; a public client's refresh family refreshes only with its key.
 */
final class DpopBindingTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;

    private const string TOKEN = 'https://auth.clavia.test/oauth2/token';
    private const string PAR = 'https://auth.clavia.test/oauth2/par';

    // ── Codes ───────────────────────────────────────────────────────────────────

    public function testACodeBoundToAKeyIsRedeemedWithIt(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $client = DpopClient::es256();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['dpop_jkt' => $client->thumbprint()]);

        $redeemed = $this->send($client, self::TOKEN, fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: self::dpop($proof),
        ));

        self::assertSame(StatusCodeInterface::STATUS_OK, $redeemed->getStatusCode(), (string) $redeemed->getBody());
        self::assertSame('DPoP', self::json($redeemed)['token_type']);
    }

    public function testABoundCodeIsUselessWithAnotherKeyAndIsSpent(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $owner = DpopClient::es256();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['dpop_jkt' => $owner->thumbprint()]);
        $redeem = fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: self::dpop($proof),
        );

        $thief = $this->send(DpopClient::es256(), self::TOKEN, $redeem);
        $owners = $this->send($owner, self::TOKEN, $redeem);

        self::assertSame('invalid_grant', self::json($thief)['error']);
        self::assertSame('invalid_grant', self::json($owners)['error'], 'Spent, like a code with a wrong verifier.');
    }

    public function testABoundCodeNeedsAProof(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['dpop_jkt' => DpopClient::es256()->thumbprint()]);

        $response = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));

        self::assertSame('invalid_grant', self::json($response)['error']);
    }

    public function testAMalformedDpopJktIsAnInvalidRequest(): void
    {
        $this->loggedIn();
        $this->publicClient();

        $params = $this->authorizeParams($this->makePkcePair()[1], ['dpop_jkt' => 'short']);

        $response = $this->get('/oauth2/authorize', $params);

        self::assertSame('invalid_request', self::locationQuery($response)['error'] ?? null);
    }

    // ── Pushed requests ─────────────────────────────────────────────────────────

    public function testAPushWithAProofBindsTheCodeToItsKey(): void
    {
        $this->loggedIn();
        $this->publicClient();
        $owner = DpopClient::es256();
        [$verifier, $challenge] = $this->makePkcePair();

        $pushed = $this->send($owner, self::PAR, fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/par',
            $this->authorizeParams($challenge),
            headers: self::dpop($proof),
        ));
        self::assertSame(StatusCodeInterface::STATUS_CREATED, $pushed->getStatusCode(), (string) $pushed->getBody());
        self::assertNotSame('', $pushed->getHeaderLine('DPoP-Nonce'));
        $requestUri = self::json($pushed)['request_uri'];
        self::assertIsString($requestUri);
        $code = $this->extractCode($this->get('/oauth2/authorize', [
            'client_id' => self::TEST_CLIENT_ID,
            'request_uri' => $requestUri,
        ]));

        $redeemed = $this->send($owner, self::TOKEN, fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: self::dpop($proof),
        ));

        self::assertSame(StatusCodeInterface::STATUS_OK, $redeemed->getStatusCode(), (string) $redeemed->getBody());
        self::assertSame('DPoP', self::json($redeemed)['token_type']);
    }

    public function testAPushedRequestsCodeIsUselessWithAnotherKey(): void
    {
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $pushed = $this->send(DpopClient::es256(), self::PAR, fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/par',
            $this->authorizeParams($challenge),
            headers: self::dpop($proof),
        ));
        $requestUri = self::json($pushed)['request_uri'];
        self::assertIsString($requestUri);
        $code = $this->extractCode($this->get('/oauth2/authorize', [
            'client_id' => self::TEST_CLIENT_ID,
            'request_uri' => $requestUri,
        ]));

        $thief = $this->send(DpopClient::es256(), self::TOKEN, fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: self::dpop($proof),
        ));

        self::assertSame('invalid_grant', self::json($thief)['error']);
    }

    public function testAPushWhoseDpopJktNamesAnotherKeyIsRefused(): void
    {
        $this->publicClient();
        $client = DpopClient::es256();
        $params = $this->authorizeParams($this->makePkcePair()[1], ['dpop_jkt' => DpopClient::es256()->thumbprint()]);

        $response = $this->send($client, self::PAR, fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/par',
            $params,
            headers: self::dpop($proof),
        ));

        self::assertSame('invalid_dpop_proof', self::json($response)['error']);
    }

    // ── Refresh tokens ──────────────────────────────────────────────────────────

    public function testAPublicClientsRefreshTokenNeedsItsKey(): void
    {
        $this->loggedIn();
        $this->refreshingClient();
        $owner = DpopClient::es256();
        $refresh = $this->boundTokens($owner)['refresh_token'];
        self::assertIsString($refresh);
        $refreshWith = fn (?string $proof): ResponseInterface => $this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'client_id' => self::TEST_CLIENT_ID,
            'refresh_token' => $refresh,
        ], headers: self::dpop($proof));

        $withoutProof = $refreshWith(null);
        $withAnotherKey = $this->send(DpopClient::es256(), self::TOKEN, $refreshWith);
        $withItsKey = $this->send($owner, self::TOKEN, $refreshWith);

        self::assertSame('invalid_grant', self::json($withoutProof)['error']);
        self::assertSame('invalid_grant', self::json($withAnotherKey)['error']);
        // Neither spent it: a wrong proof is not a replay.
        self::assertSame(StatusCodeInterface::STATUS_OK, $withItsKey->getStatusCode(), (string) $withItsKey->getBody());
        self::assertSame('DPoP', self::json($withItsKey)['token_type']);
    }

    public function testAConfidentialClientsRefreshTokenIsBoundToItsAuthenticationInstead(): void
    {
        $this->loggedIn();
        $this->confidentialClient([GrantType::AuthorizationCode, GrantType::RefreshToken]);
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID]);
        $credentials = ['client_id' => self::TEST_CONFIDENTIAL_CLIENT_ID, 'client_secret' => self::TEST_CLIENT_SECRET];
        $redeem = fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier, $credentials),
            headers: self::dpop($proof),
        );
        $tokens = self::json($this->send(DpopClient::es256(), self::TOKEN, $redeem));
        self::assertSame('DPoP', $tokens['token_type']);
        self::assertIsString($tokens['refresh_token']);

        $refreshed = $this->post('/oauth2/token', [
            'grant_type' => 'refresh_token',
            'refresh_token' => $tokens['refresh_token'],
        ] + $credentials);

        self::assertSame(StatusCodeInterface::STATUS_OK, $refreshed->getStatusCode(), (string) $refreshed->getBody());
        self::assertSame('Bearer', self::json($refreshed)['token_type']);
    }

    /** @return array<array-key, mixed> */
    private function boundTokens(DpopClient $client): array
    {
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        return self::json($this->send($client, self::TOKEN, fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: self::dpop($proof),
        )));
    }

    /**
     * Send with a proof for `$url`, retrying once with the server's nonce, as a DPoP library does.
     *
     * @param callable(?string): ResponseInterface $send Sends the request with the proof given.
     */
    private function send(DpopClient $client, string $url, callable $send): ResponseInterface
    {
        $first = $send($client->proof('POST', $url));
        if ((self::json($first)['error'] ?? null) !== 'use_dpop_nonce') {
            return $first;
        }

        return $send($client->proof('POST', $url, $first->getHeaderLine('DPoP-Nonce')));
    }

    /**
     * The header that carries a proof; none without one.
     *
     * @return array<non-empty-string, string>
     */
    private static function dpop(?string $proof): array
    {
        return $proof === null ? [] : ['DPoP' => $proof];
    }
}
