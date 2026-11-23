<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\DpopClient;
use ClaviaTest\Support\MachineFixtures;
use ClaviaTest\Support\ManagementFixtures;
use ClaviaTest\Support\OAuth2Fixtures;
use Psr\Http\Message\ResponseInterface;

/**
 * A client required to use DPoP (`dpop_bound_access_tokens`, RFC 9449 §5.2; docs/design/dpop.md,
 * slice 4): every token request it makes carries a proof, or is refused before the grant runs.
 */
final class DpopRequiredTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;
    use MachineFixtures;
    use ManagementFixtures;

    private const string CLIENTS = '/api/v1/clients';
    private const string TOKEN = 'https://auth.clavia.test/oauth2/token';

    public function testTheSettingIsReadAndWrittenInTheManagementApi(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::CLIENTS, [
            'name' => 'Banking',
            'redirect_uris' => ['https://bank.test/cb'],
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'dpop_bound_access_tokens' => true,
        ]);
        self::assertSame(201, $created->getStatusCode(), (string) $created->getBody());
        self::assertTrue(self::document($created)['dpop_bound_access_tokens']);
        $path = self::CLIENTS . '/' . rawurlencode((string) self::document($created)['client_id']);

        $patched = $this->api('PATCH', $path, ['dpop_bound_access_tokens' => false]);

        self::assertFalse(self::document($patched)['dpop_bound_access_tokens']);
        self::assertFalse(self::document($this->api('GET', $path))['dpop_bound_access_tokens']);
    }

    public function testItIsOffByDefault(): void
    {
        $this->adminToken();

        $created = $this->api('POST', self::CLIENTS, [
            'name' => 'Ordinary',
            'redirect_uris' => ['https://app.test/cb'],
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
        ]);

        self::assertFalse(self::document($created)['dpop_bound_access_tokens']);
    }

    public function testACodeIsNotRedeemedWithoutAProofAndIsNotSpent(): void
    {
        $this->loggedIn();
        $this->requireDpop($this->publicClient());
        [$verifier, $challenge] = $this->makePkcePair();
        $code = $this->authorizeAndGetCode($challenge);

        $refused = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier));
        $redeemed = $this->withProof(DpopClient::es256(), fn (string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            $this->tokenRequest($code, $verifier),
            headers: ['DPoP' => $proof],
        ));

        self::assertSame(400, $refused->getStatusCode());
        self::assertSame('invalid_dpop_proof', self::json($refused)['error']);
        // Refused before the grant ran: the code is still good, for a request carrying a proof.
        self::assertSame(200, $redeemed->getStatusCode(), (string) $redeemed->getBody());
        self::assertSame('DPoP', self::json($redeemed)['token_type']);
    }

    public function testAMachineIsNotIssuedABearerToken(): void
    {
        $this->adminToken();
        $this->requireDpop($this->clientNamed(self::TEST_M2M_CLIENT_ID));
        $request = fn (?string $proof): ResponseInterface => $this->post(
            '/oauth2/token',
            ['grant_type' => 'client_credentials', 'audience' => self::MANAGEMENT_API],
            basicAuth: [self::TEST_M2M_CLIENT_ID, self::TEST_M2M_SECRET],
            headers: $proof === null ? [] : ['DPoP' => $proof],
        );

        $refused = $request(null);
        $issued = $this->withProof(DpopClient::es256(), $request);

        self::assertSame('invalid_dpop_proof', self::json($refused)['error']);
        self::assertSame('DPoP', self::json($issued)['token_type']);
    }

    private function requireDpop(Client $client): void
    {
        $this->container()->get(ClientRepository::class)->save($client->withDpopRequired(true));
    }

    private function clientNamed(string $id): Client
    {
        $client = $this->container()->get(ClientRepository::class)->find(ClientId::fromString($id));
        self::assertNotNull($client);

        return $client;
    }

    /** @param callable(string): ResponseInterface $send */
    private function withProof(DpopClient $client, callable $send): ResponseInterface
    {
        $first = $send($client->proof('POST', self::TOKEN));
        if ((self::json($first)['error'] ?? null) !== 'use_dpop_nonce') {
            return $first;
        }

        return $send($client->proof('POST', self::TOKEN, $first->getHeaderLine('DPoP-Nonce')));
    }
}
