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
use Clavia\Adapter\Secondary\Redis\RedisConsentStateStore;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Contract\ConsentStateStoreContract;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisConsentStateStoreTest extends IntegrationTestCase
{
    use ConsentStateStoreContract;

    #[\Override]
    protected function consentStates(): ConsentStateStore
    {
        return new RedisConsentStateStore(new RedisConnection(TestEnvironment::redisUrl()));
    }

    public function testItIsStoredForItsLifetimeUnderTheHandlesDigest(): void
    {
        $this->consentStates()->park('the-plain-handle', self::minimal());

        $ttl = $this->redis()->ttl(Keys::forSecret('consent-state', 'the-plain-handle'));
        $keys = $this->redis()->keys('*');

        self::assertGreaterThan(PendingConsent::LIFETIME_SECONDS - 5, $ttl);
        self::assertLessThanOrEqual(PendingConsent::LIFETIME_SECONDS, $ttl);
        self::assertIsArray($keys);
        self::assertStringNotContainsString('the-plain-handle', implode('|', $keys));
    }

    public function testAnEntryThatCannotBeReadIsAnEntryThatIsNotThere(): void
    {
        $this->redis()->set(Keys::forSecret('consent-state', 'garbled'), '{not json');
        $this->redis()->set(Keys::forSecret('consent-state', 'wrong-shape'), '{"resume_at":42}');
        $this->redis()->set(
            Keys::forSecret('consent-state', 'bad-user'),
            '{"resume_at":"/","redirect_uri":"https://a/","user_id":"nope","client_id":"spa","scope":""}',
        );

        self::assertNull($this->consentStates()->find('garbled'));
        self::assertNull($this->consentStates()->find('wrong-shape'));
        self::assertNull($this->consentStates()->claim('bad-user'));
    }

    private static function minimal(): PendingConsent
    {
        return new PendingConsent(
            '/oauth2/authorize',
            'https://app.example/cb',
            null,
            UserId::fromString('00000000-0000-4000-8000-000000000001'),
            ClientId::fromString('spa'),
            ScopeSet::empty(),
            null,
        );
    }
}
