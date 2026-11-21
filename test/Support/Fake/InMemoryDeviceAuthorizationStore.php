<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Digest;

/**
 * Device authorizations in memory, kept until their retention runs out on the clock
 * given.
 */
final class InMemoryDeviceAuthorizationStore implements DeviceAuthorizationStore
{
    /** @var array<string, array{authorization: DeviceAuthorization, until: int}> By user code. */
    private array $byUserCode = [];

    /** @var array<string, string> User codes, by device code digest. */
    private array $byDeviceCode = [];

    public function __construct(private readonly FrozenClock $clock)
    {
    }

    #[\Override]
    public function open(DeviceAuthorization $authorization): bool
    {
        if ($this->live($authorization->userCode->value) !== null) {
            return false;
        }

        $now = $this->clock->now();
        $this->byUserCode[$authorization->userCode->value] = [
            'authorization' => clone $authorization,
            'until' => $now->getTimestamp() + $authorization->retentionFrom($now),
        ];
        $this->byDeviceCode[$authorization->deviceCode->toString()] = $authorization->userCode->value;

        return true;
    }

    #[\Override]
    public function findByDeviceCode(Digest $deviceCode): ?DeviceAuthorization
    {
        $userCode = $this->byDeviceCode[$deviceCode->toString()] ?? null;
        $found = $userCode === null ? null : $this->live($userCode);

        return $found !== null && $found->deviceCode->equals($deviceCode) ? clone $found : null;
    }

    #[\Override]
    public function findByUserCode(UserCode $userCode): ?DeviceAuthorization
    {
        $found = $this->live($userCode->value);

        return $found === null ? null : clone $found;
    }

    #[\Override]
    public function save(DeviceAuthorization $authorization): void
    {
        $key = $authorization->userCode->value;
        if ($this->live($key) !== null) {
            $this->byUserCode[$key]['authorization'] = clone $authorization;
        }
    }

    #[\Override]
    public function consume(DeviceAuthorization $authorization): bool
    {
        $key = $authorization->userCode->value;
        $found = $this->live($key);
        unset($this->byUserCode[$key], $this->byDeviceCode[$authorization->deviceCode->toString()]);

        return $found !== null;
    }

    private function live(string $userCode): ?DeviceAuthorization
    {
        $entry = $this->byUserCode[$userCode] ?? null;
        if ($entry === null || $entry['until'] <= $this->clock->now()->getTimestamp()) {
            return null;
        }

        return $entry['authorization'];
    }
}
