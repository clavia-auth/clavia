<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * The device request behind what a person typed — when there is one still to decide,
 * for an application that still exists. A code mistyped, unknown, decided, expired or
 * whose application is gone is the same nothing.
 */
final readonly class PendingDeviceRequests
{
    public function __construct(
        private DeviceAuthorizationStore $store,
        private ClientRepository $clients,
        private Clock $clock,
    ) {
    }

    /**
     * @return array{DeviceAuthorization, Client}|null
     */
    public function find(string $typed): ?array
    {
        try {
            $userCode = UserCode::fromTyped($typed);
        } catch (InvalidValue) {
            return null;
        }

        $request = $this->store->findByUserCode($userCode);
        if ($request === null || ! $request->awaitsDecisionAt($this->clock->now())) {
            return null;
        }

        $client = $this->clients->find($request->clientId);

        return $client === null ? null : [$request, $client];
    }
}
