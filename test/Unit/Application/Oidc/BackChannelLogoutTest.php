<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Oidc;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Oidc\LogoutTokenClaims;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\BackChannelLogouts;
use ClaviaTest\Support\Clients;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\TestCase;

final class BackChannelLogoutTest extends TestCase
{
    private const string URI = 'https://app.example/backchannel';

    private FrozenClock $clock;
    private InMemoryClientRepository $clients;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->clients = new InMemoryClientRepository();
        $this->clients->save(
            Clients::public('spa')->withBackChannelLogout(new BackChannelLogout(Url::fromString(self::URI))),
        );
        $this->clients->save(Clients::public('quiet'));
    }

    public function testNothingIsSentBeforeTheResponseAndOneTokenPerApplicationAfter(): void
    {
        [$backChannel, $tasks, $delivery] = BackChannelLogouts::for($this->clients, $this->clock);

        $backChannel->sessionsEnded($this->session('spa', 'quiet', 'deleted'), null, $this->session());

        self::assertCount(0, $delivery->delivered, 'Deferred until after the response.');
        self::assertSame(3, $tasks->count(), 'One task per application.');
        $tasks->run();
        $delivered = $delivery->delivered;
        self::assertCount(1, $delivered, 'Only the application that asked to be told.');
        self::assertSame('spa', $delivered[0]['client'] ?? null);
        self::assertSame(self::URI, $delivered[0]['uri'] ?? null);
    }

    public function testTheTokenIsALogoutTokenForThatApplicationAndSession(): void
    {
        [$backChannel, $tasks, $delivery] = BackChannelLogouts::for($this->clients, $this->clock);
        $session = $this->session('spa');

        $backChannel->sessionsEnded($session);
        $tasks->run();

        $parts = explode('.', $delivery->delivered[0]['token'] ?? '');
        self::assertCount(3, $parts);
        $encodedHeader = $parts[0];
        $encodedClaims = $parts[1] ?? '';
        /** @var mixed $header */
        $header = json_decode(Base64Url::decode($encodedHeader), true, flags: JSON_THROW_ON_ERROR);
        /** @var mixed $claims */
        $claims = json_decode(Base64Url::decode($encodedClaims), true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($header);
        self::assertIsArray($claims);
        self::assertSame('logout+jwt', $header['typ'] ?? null);
        self::assertSame(BackChannelLogouts::ISSUER, $claims['iss'] ?? null);
        self::assertSame('spa', $claims['aud'] ?? null);
        self::assertSame($session->userId->value, $claims['sub'] ?? null);
        self::assertSame('sid-1', $claims['sid'] ?? null);
        self::assertSame($this->clock->now()->getTimestamp(), $claims['iat'] ?? null);
        self::assertSame($this->clock->now()->getTimestamp() + 120, $claims['exp'] ?? null);
        self::assertSame([LogoutTokenClaims::EVENT => []], $claims['events'] ?? null);
        self::assertArrayNotHasKey('nonce', $claims);
    }

    private function session(string ...$clients): Session
    {
        return Session::reconstitute(
            UserId::generate(new SeededRandomSource(4)),
            $this->clock->now()->modify('-1 hour'),
            $this->clock->now()->modify('+1 hour'),
            [AuthenticationMethod::Password],
            'sid-1',
            ConnectionName::defaultPool(),
            array_values(array_map(ClientId::fromString(...), $clients)),
        );
    }
}
