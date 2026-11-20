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
use Clavia\Adapter\Secondary\Redis\RedisExternalSignInStore;
use Clavia\Application\Port\ExternalSignInStore;
use Clavia\Domain\Authentication\PendingExternalSignIn;
use Clavia\Domain\Identity\ProviderName;
use Clavia\Domain\OAuth2\CodeVerifier;
use ClaviaTest\Support\Contract\ExternalSignInStoreContract;
use ClaviaTest\Support\Fake\SeededRandomSource;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisExternalSignInStoreTest extends IntegrationTestCase
{
    use ExternalSignInStoreContract;

    #[\Override]
    protected function pendingSignIns(): ExternalSignInStore
    {
        return new RedisExternalSignInStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testItIsStoredForItsLifetimeUnderADigestOfTheState(): void
    {
        $this->pendingSignIns()->open('the-plain-state', $this->pending());

        $keys = $this->redis()->keys('*');
        $ttl = $this->redis()->ttl(Keys::forSecret('external-sign-in', 'the-plain-state'));

        self::assertIsArray($keys);
        self::assertCount(1, $keys);
        self::assertStringNotContainsString('the-plain-state', implode('|', $keys));
        self::assertGreaterThan(PendingExternalSignIn::LIFETIME_SECONDS - 5, $ttl);
        self::assertLessThanOrEqual(PendingExternalSignIn::LIFETIME_SECONDS, $ttl);
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThereAndIsStillSpent(): void
    {
        $entries = [
            'garbled' => '{not json',
            'wrong-shape' => '{"provider":42}',
            'bad-provider' => '{"provider":"Not A Name","code_verifier":"' . str_repeat('a', 43) . '","next_url":"/"}',
            'bad-verifier' => '{"provider":"google","code_verifier":"short","next_url":"/"}',
        ];
        foreach ($entries as $handle => $value) {
            $this->redis()->set(Keys::forSecret('external-sign-in', $handle), $value);
        }

        foreach (array_keys($entries) as $handle) {
            self::assertNull($this->pendingSignIns()->claim($handle));
        }
        self::assertSame(0, $this->redis()->dbSize());
    }

    private function pending(): PendingExternalSignIn
    {
        return new PendingExternalSignIn(
            ProviderName::fromString('google'),
            CodeVerifier::generate(new SeededRandomSource()),
            '/',
            null,
            null,
        );
    }
}
