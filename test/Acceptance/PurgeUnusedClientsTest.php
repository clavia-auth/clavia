<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use Clavia\Adapter\Primary\Cli\PurgeUnusedClientsCommand;
use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\NewInitialAccessToken;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\OAuth2Fixtures;
use ClaviaTest\Support\TestStorage;
use Fig\Http\Message\StatusCodeInterface;
use Symfony\Component\Console\Tester\CommandTester;

/**
 * Self-registered clients never used are purged (docs/design/dynamic-client-registration.md §5.4,
 * slice 5): one never issued a token is deleted past `CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME`;
 * one used once, one still within its lifetime and every operator's client are kept.
 */
final class PurgeUnusedClientsTest extends AcceptanceTestCase
{
    use OAuth2Fixtures;

    private const string REDIRECT_URI = 'http://127.0.0.1:8400/callback';

    public function testOnlyAClientNeverUsedPastItsLifetimeIsDeleted(): void
    {
        $this->boot([
            'CLAVIA_CLIENT_REGISTRATION' => 'token',
            'CLAVIA_CLIENT_REGISTRATION_UNUSED_LIFETIME' => '30',
            'CLAVIA_DEV_AUTOLOGIN_EMAIL' => self::TEST_USER_EMAIL,
        ]);
        $clock = $this->freezeClock('2026-01-01T10:00:00Z');
        $this->publicClient();
        $unused = $this->registered('Never used');
        $used = $this->registered('Used once');
        $this->signIn($used);
        $clock->advance(29 * 86_400);
        $recent = $this->registered('Registered lately');
        $clock->advance(2 * 86_400);

        $tester = new CommandTester($this->container()->get(PurgeUnusedClientsCommand::class));
        self::assertSame(0, $tester->execute([]));

        self::assertSame("Deleted 1 unused self-registered client.\n", $tester->getDisplay(true));
        $clients = $this->container()->get(ClientRepository::class);
        self::assertNull($clients->find($unused));
        self::assertNotNull($clients->find($used));
        self::assertNotNull($clients->find($recent));
        self::assertNotNull($clients->find(ClientId::fromString(self::TEST_CLIENT_ID)), "An operator's client.");
        self::assertSame(1, (int) TestStorage::database()->fetchValue(
            'SELECT count(*) FROM audit_events WHERE type = :type',
            ['type' => AuditEventType::ClientDeleted->value],
        ));
        $tester->execute([]);
        self::assertSame("No self-registered client is unused past its lifetime.\n", $tester->getDisplay(true));
    }

    /** A public native client, registered with a fresh initial access token. */
    private function registered(string $name): ClientId
    {
        $token = $this->container()->get(IssueInitialAccessToken::class)(new NewInitialAccessToken($name))->secret;
        $response = $this->request('POST', '/oauth2/register', [
            'Authorization' => 'Bearer ' . $token,
            'Content-Type' => 'application/json',
        ], body: (string) json_encode([
            'client_name' => $name,
            'token_endpoint_auth_method' => 'none',
            'redirect_uris' => [self::REDIRECT_URI],
        ]));
        $clientId = self::json($response)['client_id'] ?? null;
        self::assertIsString($clientId, (string) $response->getBody());

        return ClientId::fromString($clientId);
    }

    /** A code flow to its end, the person having consented already: the client's first token. */
    private function signIn(ClientId $client): void
    {
        $this->container()->get(ConsentRepository::class)->save(UserConsent::give(
            $this->user()->id,
            $client,
            null,
            ScopeSet::fromString('openid profile'),
            new \DateTimeImmutable('2026-01-01T10:00:00Z'),
        ));
        [$verifier, $challenge] = $this->makePkcePair();
        $overrides = ['client_id' => $client->value, 'redirect_uri' => self::REDIRECT_URI];
        $code = $this->authorizeAndGetCode($challenge, $overrides);

        $token = $this->post('/oauth2/token', $this->tokenRequest($code, $verifier, $overrides));

        self::assertSame(StatusCodeInterface::STATUS_OK, $token->getStatusCode(), (string) $token->getBody());
    }
}
