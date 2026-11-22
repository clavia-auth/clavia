<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Redis;

use Clavia\Adapter\Secondary\Redis\Keys;
use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisWebAuthnChallengeStore;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use ClaviaTest\Support\Contract\WebAuthnChallengeStoreContract;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;
use DateTimeImmutable;

final class RedisWebAuthnChallengeStoreTest extends IntegrationTestCase
{
    use WebAuthnChallengeStoreContract;

    #[\Override]
    protected function ceremonies(): WebAuthnChallengeStore
    {
        return new RedisWebAuthnChallengeStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testItIsStoredForItsLifetimeUnderTheHandlesDigest(): void
    {
        $this->ceremonies()->open('the-plain-handle', self::signIn(), 120);

        $ttl = $this->redis()->ttl(Keys::forSecret('webauthn', 'the-plain-handle'));
        $keys = $this->redis()->keys('*');

        self::assertGreaterThan(115, $ttl);
        self::assertLessThanOrEqual(120, $ttl);
        self::assertIsArray($keys);
        self::assertStringNotContainsString('the-plain-handle', implode('|', $keys));
    }

    public function testNeitherTheLoginStateNorTheHandleIsStoredInTheClear(): void
    {
        $this->ceremonies()->open('the-plain-handle', self::signIn(), 120);

        $stored = $this->redis()->get(Keys::forSecret('webauthn', 'the-plain-handle'));

        self::assertIsString($stored);
        self::assertStringNotContainsString('the-login-state', $stored);
        self::assertStringNotContainsString('the-plain-handle', $stored);
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThere(): void
    {
        $this->redis()->set(Keys::forSecret('webauthn', 'garbled'), '{not json');
        $this->redis()->set(Keys::forSecret('webauthn', 'wrong-shape'), '{"challenge":42}');
        $this->redis()->set(
            Keys::forSecret('webauthn', 'short-challenge'),
            '{"challenge":"AAAA","purpose":"registration","user_id":"00000000-0000-4000-8000-000000000001",'
            . '"context":null,"expires_at":"2026-01-15T10:00:00.000000+00:00"}',
        );
        $this->redis()->set(
            Keys::forSecret('webauthn', 'unknown-purpose'),
            '{"challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","purpose":"nope","user_id":null,'
            . '"context":null,"expires_at":"2026-01-15T10:00:00.000000+00:00"}',
        );

        foreach (['garbled', 'wrong-shape', 'short-challenge', 'unknown-purpose'] as $handle) {
            self::assertNull($this->ceremonies()->claim($handle), $handle);
        }
    }

    private static function signIn(): WebAuthnChallenge
    {
        return WebAuthnChallenge::forSignIn(
            new SeededRandomSource(1),
            'the-login-state',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            120,
        );
    }
}
