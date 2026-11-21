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
use Clavia\Adapter\Secondary\Redis\RedisDeviceAuthorizationStore;
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Contract\DeviceAuthorizationStoreContract;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisDeviceAuthorizationStoreTest extends IntegrationTestCase
{
    use DeviceAuthorizationStoreContract;

    private ?FrozenClock $clock = null;

    #[\Override]
    protected function deviceRequests(): DeviceAuthorizationStore
    {
        return new RedisDeviceAuthorizationStore(
            new RedisConnection(TestEnvironment::redisUrl()),
            $this->deviceClock(),
        );
    }

    #[\Override]
    protected function deviceClock(): FrozenClock
    {
        // Real time: Redis expires entries on its own clock.
        return $this->clock ??= new FrozenClock(gmdate('Y-m-d\TH:i:s\Z'));
    }

    public function testBothCodesAreKeptForTheRequestsLifeAndTheGraceNeitherInTheClear(): void
    {
        $this->deviceRequests()->open($this->aRequest());

        $keys = $this->redis()->keys('*');
        self::assertIsArray($keys);
        self::assertCount(2, $keys);
        self::assertStringNotContainsString('the-device-code', implode('|', $keys));
        self::assertStringNotContainsString('BCDF', implode('|', $keys));
        foreach ($keys as $key) {
            $ttl = $this->redis()->ttl($key);
            self::assertGreaterThan(655, $ttl);
            self::assertLessThanOrEqual(660, $ttl);
            $value = $this->redis()->get($key);
            self::assertIsString($value);
            self::assertStringNotContainsString('the-device-code', $value);
        }
    }

    public function testSavingKeepsTheRetention(): void
    {
        $request = $this->aRequest();
        $this->deviceRequests()->open($request);
        $key = Keys::forSecret('device-request', 'BCDF-GHJK');
        $this->redis()->expire($key, 100);

        $request->poll($this->deviceClock()->now());
        $this->deviceRequests()->save($request);

        self::assertLessThanOrEqual(100, $this->redis()->ttl($key));
    }

    public function testAnEntryThatCannotBeReadIsNoRequest(): void
    {
        $this->redis()->set(Keys::forSecret('device-request', 'BCDF-GHJK'), '{not json');
        $this->redis()->set(Keys::forIdentifier('device-code', Digest::of('x')->toString()), 'BCDF-GHJK');

        self::assertNull($this->deviceRequests()->findByUserCode(UserCode::fromTyped('BCDF-GHJK')));
        self::assertNull($this->deviceRequests()->findByDeviceCode(Digest::of('x')));
    }

    private function aRequest(): DeviceAuthorization
    {
        return DeviceAuthorization::request(
            Digest::of('the-device-code'),
            UserCode::fromTyped('BCDF-GHJK'),
            ClientId::fromString('tv'),
            ScopeSet::fromString('openid'),
            null,
            $this->deviceClock()->now(),
            600,
            5,
        );
    }
}
