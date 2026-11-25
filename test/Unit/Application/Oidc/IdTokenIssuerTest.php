<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Oidc;

use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use Clavia\Application\Oidc\ApplicationClaims;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Oidc\IdTokenIssuer;
use Clavia\Application\Port\NoActiveSigningKey;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Base64Url;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use ClaviaTest\Support\Fake\SeededRandomSource;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\RS256;
use PHPUnit\Framework\TestCase;

final class IdTokenIssuerTest extends TestCase
{
    private FrozenClock $clock;
    private InMemorySigningKeys $keys;
    private IdTokenIssuer $issuer;
    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->keys = new InMemorySigningKeys($this->clock);
        $this->issuer = new IdTokenIssuer(
            $this->keys,
            new CompactJws($this->keys),
            'https://auth.clavia.test',
            300,
            new ApplicationClaims(new InMemoryClientRepository(), new InMemoryRoleRepository()),
        );
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(5)),
            'ada@example.com',
            null,
            $this->clock->now(),
        );
    }

    public function testTheTokenIsACompactJwsSignedByTheActiveKey(): void
    {
        $key = $this->keys->create(SigningAlgorithm::RS256, $this->clock->now());

        $token = $this->issuer->issue($this->code(), $this->user, 'the-access-token', $this->clock->now());

        $parts = explode('.', $token);
        self::assertCount(3, $parts);
        [$header, $payload, $signature] = $parts;
        self::assertSame(
            ['alg' => 'RS256', 'typ' => 'JWT', 'kid' => $key->kid()],
            json_decode(Base64Url::decode($header), true),
        );
        self::assertTrue(self::verifies($key->publicJwk, $header . '.' . $payload, Base64Url::decode($signature)));
    }

    public function testTheClaimsComeFromTheCodeAndTheAccessToken(): void
    {
        $this->keys->create(SigningAlgorithm::RS256, $this->clock->now());

        $token = $this->issuer->issue($this->code(), $this->user, 'the-access-token', $this->clock->now());

        /** @var array<string, mixed> $claims */
        $claims = json_decode(Base64Url::decode(explode('.', $token)[1]), true);
        self::assertSame('https://auth.clavia.test', $claims['iss']);
        self::assertSame('spa', $claims['aud']);
        self::assertSame($this->user->id->value, $claims['sub']);
        self::assertSame('n-1', $claims['nonce']);
        self::assertSame(SigningAlgorithm::RS256->halfHash('the-access-token'), $claims['at_hash']);
        self::assertSame($this->clock->now()->getTimestamp() + 300, $claims['exp']);
        self::assertArrayNotHasKey('email', $claims, 'The scope releases it at userinfo, not here.');
    }

    public function testWithoutAnActiveKeyNothingIsIssued(): void
    {
        $this->expectException(NoActiveSigningKey::class);
        $this->expectExceptionMessageIsOrContains('clavia keys:generate');

        $this->issuer->issue($this->code(), $this->user, 'the-access-token', $this->clock->now());
    }

    public function testTheJsonIsCompactAndKeepsSlashesAndUnicodeAsTheyAre(): void
    {
        $this->keys->create(SigningAlgorithm::RS256, $this->clock->now());
        $jws = new CompactJws($this->keys);

        $token = $jws->sign($this->keys->activeKey(), ['url' => 'https://a.example/x', 'name' => 'Zoë'], 'JWT');

        self::assertSame(
            '{"url":"https://a.example/x","name":"Zoë"}',
            Base64Url::decode(explode('.', $token)[1]),
        );
    }

    public function testAnotherTypeCanBeNamed(): void
    {
        $this->keys->create(SigningAlgorithm::RS256, $this->clock->now());

        $token = new CompactJws($this->keys)->sign($this->keys->activeKey(), ['a' => 1], 'logout+jwt');

        /** @var array{typ: string} $header */
        $header = json_decode(Base64Url::decode(explode('.', $token)[0]), true);
        self::assertSame('logout+jwt', $header['typ']);
    }

    private function code(): AuthorizationCode
    {
        return AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(1)),
            Digest::of('the-code'),
            ClientId::fromString('spa'),
            $this->user->id,
            'https://app.example/cb',
            ScopeSet::fromString('openid email'),
            CodeChallenge::fromString(str_repeat('a', 43)),
            null,
            Nonce::fromString('n-1'),
            AuthenticationContext::unknown(),
            $this->clock->now(),
            60,
        );
    }

    private static function verifies(PublicJwk $jwk, string $input, string $signature): bool
    {
        return new RS256()->verify(new JWK($jwk->toArray()), $input, $signature);
    }
}
