<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Development;

use Clavia\Application\Development\BuildAuthorizationUrl;
use Clavia\Application\Development\SeedDevelopmentData;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class BuildAuthorizationUrlTest extends TestCase
{
    private InMemoryClientRepository $clients;
    private BuildAuthorizationUrl $build;

    #[\Override]
    protected function setUp(): void
    {
        $random = new SeededRandomSource(1);
        $this->clients = new InMemoryClientRepository();
        $this->build = new BuildAuthorizationUrl(
            $this->clients,
            new SecretGenerator($random),
            $random,
            ScopeSet::fromString('openid profile email'),
        );
    }

    public function testItDefaultsToTheSeededClientAndEveryScope(): void
    {
        $this->seedTheDevelopmentClient('seeded-client');

        $url = ($this->build)(null, 'http://localhost:3000/callback', null);

        self::assertNotNull($url);
        self::assertSame('seeded-client', $url->clientId->value);
        self::assertSame('http://localhost:3000/callback', $url->redirectUri);
        self::assertSame(
            ['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method'],
            array_keys($url->parameters),
        );
        self::assertSame('code', $url->parameters['response_type']);
        self::assertSame('seeded-client', $url->parameters['client_id']);
        self::assertSame('http://localhost:3000/callback', $url->parameters['redirect_uri']);
        self::assertSame('openid profile email', $url->parameters['scope']);
        self::assertSame('S256', $url->parameters['code_challenge_method']);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{22}$/D', $url->parameters['state']);
    }

    public function testTheChallengeInTheUrlIsTheOneOfTheVerifierItHandsBack(): void
    {
        $this->seedTheDevelopmentClient('seeded-client');

        $url = ($this->build)(null, 'http://localhost:3000/callback', null);

        self::assertNotNull($url);
        self::assertTrue(CodeChallenge::fromString($url->parameters['code_challenge'])->isSatisfiedBy($url->verifier));
    }

    public function testEachUrlHasItsOwnStateAndPkcePair(): void
    {
        $this->seedTheDevelopmentClient('seeded-client');

        $first = ($this->build)(null, 'http://localhost:3000/callback', null);
        $second = ($this->build)(null, 'http://localhost:3000/callback', null);

        self::assertNotSame($first?->parameters['state'], $second?->parameters['state']);
        self::assertNotSame($first?->verifier->value, $second?->verifier->value);
    }

    public function testAnExplicitClientAndScopeWin(): void
    {
        $this->seedTheDevelopmentClient('seeded-client');

        $url = ($this->build)(ClientId::fromString('mine'), 'https://app.example/cb', ScopeSet::fromString('openid'));

        self::assertNotNull($url);
        self::assertSame('mine', $url->parameters['client_id']);
        self::assertSame('openid', $url->parameters['scope']);
    }

    public function testWithoutAClientIdAndWithoutASeededClientThereIsNothingToBuild(): void
    {
        self::assertNull(($this->build)(null, 'http://localhost:3000/callback', null));
    }

    private function seedTheDevelopmentClient(string $id): void
    {
        $this->clients->save(Client::register(
            ClientId::fromString($id),
            SeedDevelopmentData::CLIENT_NAME,
            ClientType::Public,
            ClientAuthMethod::None,
            null,
            [Url::fromString('http://localhost:3000/callback')],
            [GrantType::AuthorizationCode],
            [ResponseType::Code],
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        ));
    }
}
