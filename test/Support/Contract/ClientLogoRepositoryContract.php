<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Client\ClientLogoRepository;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\TestImages;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see ClientLogoRepository} must do, run against the double and PostgreSQL.
 */
trait ClientLogoRepositoryContract
{
    abstract protected function clientLogos(): ClientLogoRepository;

    abstract protected function clients(): ClientRepository;

    #[Test]
    public function aLogoIsReadBackByteForByte(): void
    {
        $client = $this->aClientForItsLogo();
        $logo = ClientLogo::fromBytes($client, TestImages::png(48, 32));

        $this->clientLogos()->save($logo);

        $stored = $this->clientLogos()->find($client);
        self::assertNotNull($stored);
        self::assertSame($logo->content, $stored->content);
        self::assertSame('image/png', $stored->mediaType);
        self::assertSame($logo->version, $this->clientLogos()->versionOf($client));
        self::assertSame(
            [$client->value => $logo->version],
            $this->clientLogos()->versionsOf([$client, ClientId::fromString('no-logo-here')]),
        );
        self::assertSame([], $this->clientLogos()->versionsOf([]));
    }

    #[Test]
    public function aNewLogoReplacesTheOldOne(): void
    {
        $client = $this->aClientForItsLogo();
        $this->clientLogos()->save(ClientLogo::fromBytes($client, TestImages::png(32, 32)));
        $second = ClientLogo::fromBytes($client, TestImages::png(64, 64));

        $this->clientLogos()->save($second);

        self::assertSame($second->version, $this->clientLogos()->versionOf($client));
    }

    #[Test]
    public function aRemovedLogoIsGone(): void
    {
        $client = $this->aClientForItsLogo();
        $this->clientLogos()->save(ClientLogo::fromBytes($client, TestImages::png()));

        self::assertTrue($this->clientLogos()->delete($client));
        self::assertFalse($this->clientLogos()->delete($client), 'Nothing left to remove.');
        self::assertNull($this->clientLogos()->find($client));
        self::assertNull($this->clientLogos()->versionOf($client));
    }

    private function aClientForItsLogo(): ClientId
    {
        $this->clients()->save(Client::register(
            ClientId::fromString('branded-app'),
            'Branded app',
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('https://branded.example/cb')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));

        return ClientId::fromString('branded-app');
    }
}
