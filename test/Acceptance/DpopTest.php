<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\ResourceServer\AccessTokenFormat;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\DpopClient;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\OidcFixtures;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * DPoP proofs at the token endpoint (RFC 9449; docs/design/dpop.md, slice 1): a client that
 * proves possession of a key gets an access token bound to it — `token_type: DPoP`, `cnf.jkt`
 * in the JWT and in introspection — after the server's nonce; one that does not gets a bearer
 * token, as before.
 */
final class DpopTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use OidcFixtures;

    private const string TOKEN_ENDPOINT = 'https://auth.clavia.test/oauth2/token';

    public function testDiscoveryListsTheAlgorithms(): void
    {
        $document = self::json($this->get('/.well-known/openid-configuration'));

        self::assertSame(['ES256', 'EdDSA', 'RS256'], $document['dpop_signing_alg_values_supported']);
    }

    public function testAProofWithoutTheServersNonceIsAskedForIt(): void
    {
        $this->machineApi();

        $response = $this->machineToken(DpopClient::es256()->proof('POST', self::TOKEN_ENDPOINT));

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $response->getStatusCode());
        self::assertSame('use_dpop_nonce', self::json($response)['error']);
        self::assertNotSame('', $response->getHeaderLine('DPoP-Nonce'));
    }

    public function testAProofWithTheNonceGetsABoundToken(): void
    {
        $this->container()->get(ResourceServerRepository::class)
            ->save($this->machineApi()->issuingAccessTokensAs(AccessTokenFormat::Jwt));
        $client = DpopClient::es256();

        $response = $this->withNonce($client, fn (string $proof): ResponseInterface => $this->machineToken($proof));

        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode(), (string) $response->getBody());
        $body = self::json($response);
        self::assertSame('DPoP', $body['token_type']);
        self::assertNotSame('', $response->getHeaderLine('DPoP-Nonce'), 'The next nonce, without a round trip.');
        self::assertIsString($body['access_token']);
        self::assertSame(['jkt' => $client->thumbprint()], $this->verifiedJwt($body['access_token'])['claims']['cnf']);

        $introspected = self::json($this->post(
            '/oauth2/introspect',
            ['token' => $body['access_token']],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
        ));
        self::assertSame('DPoP', $introspected['token_type']);
        self::assertSame(['jkt' => $client->thumbprint()], $introspected['cnf']);
    }

    public function testWithoutAProofATokenIsABearerTokenAsBefore(): void
    {
        $this->machineApi();

        $body = self::json($this->requestMachineToken());

        self::assertSame('Bearer', $body['token_type']);
    }

    public function testEveryAlgorithmOffered(): void
    {
        $this->machineApi();

        foreach ([DpopClient::es256(), DpopClient::edDsa(), DpopClient::rs256()] as $client) {
            $response = $this->withNonce($client, fn (string $proof): ResponseInterface => $this->machineToken($proof));
            self::assertSame('DPoP', self::json($response)['token_type'] ?? null, $client->algorithm);
        }
    }

    public function testAProofIsGoodOnce(): void
    {
        $this->machineApi();
        $client = DpopClient::es256();
        $nonce = $this->machineToken($client->proof('POST', self::TOKEN_ENDPOINT))->getHeaderLine('DPoP-Nonce');
        $proof = $client->proof('POST', self::TOKEN_ENDPOINT, $nonce);

        self::assertSame(StatusCodeInterface::STATUS_OK, $this->machineToken($proof)->getStatusCode());
        $again = $this->machineToken($proof);

        self::assertSame(StatusCodeInterface::STATUS_BAD_REQUEST, $again->getStatusCode());
        self::assertSame('invalid_dpop_proof', self::json($again)['error']);
        self::assertTrue($this->logger->hasRecordContaining('replayed'), 'The reason is in the log.');
    }

    public function testAProofForAnotherRequestIsRefused(): void
    {
        $this->machineApi();
        $client = DpopClient::es256();
        $nonce = $this->machineToken($client->proof('POST', self::TOKEN_ENDPOINT))->getHeaderLine('DPoP-Nonce');

        $forTheWrongUrl = $client->proof('POST', 'https://auth.clavia.test/oauth2/par', $nonce);
        $forTheWrongMethod = $client->proof('GET', self::TOKEN_ENDPOINT, $nonce);
        $tooOld = $client->proof('POST', self::TOKEN_ENDPOINT, $nonce, issuedAt: time() - 120);

        foreach ([$forTheWrongUrl, $forTheWrongMethod, $tooOld] as $proof) {
            $response = $this->machineToken($proof);
            self::assertSame('invalid_dpop_proof', self::json($response)['error']);
            // One answer, whatever was wrong.
            self::assertSame(
                'The DPoP proof is not valid for this request.',
                self::json($response)['error_description'],
            );
        }
    }

    public function testTwoProofsAreNone(): void
    {
        $this->machineApi();
        $client = DpopClient::es256();

        $response = $this->post(
            '/oauth2/token',
            ['grant_type' => 'client_credentials', 'audience' => self::TEST_M2M_AUDIENCE],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
            // Two proofs, as one header joined by a comma, the way a proxy would join two headers.
            headers: ['DPoP' => $client->proof('POST', self::TOKEN_ENDPOINT)
                . ', ' . $client->proof('POST', self::TOKEN_ENDPOINT)],
        );

        self::assertSame('invalid_dpop_proof', self::json($response)['error']);
    }

    public function testABadProofSpendsNoCode(): void
    {
        // The proof is read before the grant runs: a client that got it wrong still has its code.
        $this->loggedIn();
        $this->publicClient();
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge, ['scope' => 'openid']);
        $client = DpopClient::es256();

        $request = $this->tokenRequest($code, $verifier);
        $refused = $this->post('/oauth2/token', $request, headers: ['DPoP' => 'not.a.proof']);
        $redeemed = $this->withNonce($client, fn (string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: ['DPoP' => $proof],
        ));

        self::assertSame('invalid_dpop_proof', self::json($refused)['error']);
        self::assertSame(StatusCodeInterface::STATUS_OK, $redeemed->getStatusCode(), (string) $redeemed->getBody());
        self::assertSame('DPoP', self::json($redeemed)['token_type']);
    }

    private function machineToken(string $proof): ResponseInterface
    {
        return $this->post(
            '/oauth2/token',
            ['grant_type' => 'client_credentials', 'audience' => self::TEST_M2M_AUDIENCE],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
            headers: ['DPoP' => $proof],
        );
    }

    /**
     * What a DPoP client library does: try, and on `use_dpop_nonce` retry with the nonce given.
     *
     * @param callable(string): ResponseInterface $send
     */
    private function withNonce(DpopClient $client, callable $send): ResponseInterface
    {
        $first = $send($client->proof('POST', self::TOKEN_ENDPOINT));
        if ((self::json($first)['error'] ?? null) !== 'use_dpop_nonce') {
            return $first;
        }

        return $send($client->proof('POST', self::TOKEN_ENDPOINT, $first->getHeaderLine('DPoP-Nonce')));
    }
}
