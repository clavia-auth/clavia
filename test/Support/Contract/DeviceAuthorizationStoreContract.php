<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\DeviceDecision;
use Clavia\Domain\OAuth2\DevicePoll;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\FrozenClock;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see DeviceAuthorizationStore} must do. Expiry is asserted by each
 * implementation's own test.
 */
trait DeviceAuthorizationStoreContract
{
    abstract protected function deviceRequests(): DeviceAuthorizationStore;

    /** The clock the store was given. */
    abstract protected function deviceClock(): FrozenClock;

    #[Test]
    public function anOpenedRequestIsFoundByEitherCodeWhole(): void
    {
        self::assertTrue($this->deviceRequests()->open($this->aDeviceRequest('device-1', 'BCDF-GHJK')));

        $byDevice = $this->deviceRequests()->findByDeviceCode(Digest::of('device-1'));
        $byUser = $this->deviceRequests()->findByUserCode(UserCode::fromTyped('bcdf ghjk'));

        foreach ([$byDevice, $byUser] as $found) {
            self::assertNotNull($found);
            self::assertTrue($found->deviceCode->equals(Digest::of('device-1')));
            self::assertSame('BCDF-GHJK', $found->userCode->value);
            self::assertSame('tv', $found->clientId->value);
            self::assertSame('openid invoices:read', $found->scope->toString());
            self::assertSame('https://invoices.example/', $found->audience?->value);
            self::assertEquals($this->deviceClock()->now()->modify('+600 seconds'), $found->expiresAt);
            self::assertSame(5, $found->interval());
            self::assertSame(DeviceDecision::Pending, $found->decision());
            self::assertNull($found->lastPolledAt());
            self::assertNull($found->userId());
        }
        self::assertNull($this->deviceRequests()->findByDeviceCode(Digest::of('device-2')));
        self::assertNull($this->deviceRequests()->findByUserCode(UserCode::fromTyped('BCDF-GHJL')));
    }

    #[Test]
    public function aUserCodeStandsForOneLiveRequest(): void
    {
        self::assertTrue($this->deviceRequests()->open($this->aDeviceRequest('device-1', 'BCDF-GHJK')));

        self::assertFalse($this->deviceRequests()->open($this->aDeviceRequest('device-2', 'BCDF-GHJK')));

        self::assertNull($this->deviceRequests()->findByDeviceCode(Digest::of('device-2')));
        self::assertTrue(
            $this->deviceRequests()->findByUserCode(UserCode::fromTyped('BCDF-GHJK'))?->deviceCode
                ->equals(Digest::of('device-1')),
        );
    }

    #[Test]
    public function aPollAndADecisionAreSavedWhole(): void
    {
        $request = $this->aDeviceRequest('device-1', 'BCDF-GHJK');
        $this->deviceRequests()->open($request);
        $now = $this->deviceClock()->now();
        $request->poll($now);
        $request->poll($now->modify('+1 second'));
        $user = UserId::fromString('00000000-0000-4000-8000-000000000001');
        $request->approve(
            $user,
            AuthenticationContext::reconstitute($now->modify('-1 minute'), [AuthenticationMethod::Password]),
            $now,
        );

        $this->deviceRequests()->save($request);

        $found = $this->deviceRequests()->findByDeviceCode(Digest::of('device-1'));
        self::assertNotNull($found);
        self::assertSame(DeviceDecision::Approved, $found->decision());
        self::assertSame(10, $found->interval());
        self::assertEquals($now->modify('+1 second'), $found->lastPolledAt());
        self::assertSame($user->value, $found->userId()?->value);
        self::assertSame(['pwd'], $found->authentication()?->methodValues());
        self::assertEquals($now->modify('-1 minute'), $found->authentication()?->authenticatedAt);
        self::assertSame(DevicePoll::Approved, $found->poll($now->modify('+2 seconds')));
    }

    #[Test]
    public function aRequestIsConsumedOnce(): void
    {
        $request = $this->aDeviceRequest('device-1', 'BCDF-GHJK');
        $this->deviceRequests()->open($request);

        self::assertTrue($this->deviceRequests()->consume($request));
        self::assertFalse($this->deviceRequests()->consume($request));

        self::assertNull($this->deviceRequests()->findByDeviceCode(Digest::of('device-1')));
        self::assertNull($this->deviceRequests()->findByUserCode(UserCode::fromTyped('BCDF-GHJK')));
        // Saving what was consumed does not bring it back.
        $this->deviceRequests()->save($request);
        self::assertNull($this->deviceRequests()->findByUserCode(UserCode::fromTyped('BCDF-GHJK')));
    }

    private function aDeviceRequest(string $deviceCode, string $userCode): DeviceAuthorization
    {
        return DeviceAuthorization::request(
            Digest::of($deviceCode),
            UserCode::fromTyped($userCode),
            ClientId::fromString('tv'),
            ScopeSet::fromString('openid invoices:read'),
            Audience::fromString('https://invoices.example/'),
            $this->deviceClock()->now(),
            600,
            5,
        );
    }
}
