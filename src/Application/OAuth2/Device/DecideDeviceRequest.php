<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

use Clavia\Application\Authentication\EndUser;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\DeviceAuthorizationStore;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Clock;

/**
 * `POST /auth/device`: the person allows the device, or refuses it.
 *
 * What `/oauth2/authorize` checks before a code exists is checked before an approval is
 * recorded: the session counts for the application only through a connection it
 * enables, and on an API that enforces roles the person holds something there (the
 * scope is narrowed to their roles again when the device redeems, as at every
 * issuance). An approval is recorded as a consent too — the device flow always asks —
 * so it is visible to operators and withdrawable like any other.
 */
final readonly class DecideDeviceRequest
{
    public function __construct(
        private PendingDeviceRequests $pending,
        private DeviceAuthorizationStore $store,
        private ConnectionAccess $connections,
        private ResourceServerRepository $resourceServers,
        private RoleRepository $roles,
        private ConsentRepository $consents,
        private Clock $clock,
    ) {
    }

    /**
     * @return DeviceDecided|DeviceSignInRequired|null Null when the code stands for nothing to decide.
     */
    public function __invoke(string $typed, EndUser $endUser, bool $allow): DeviceDecided|DeviceSignInRequired|null
    {
        $found = $this->pending->find($typed);
        if ($found === null) {
            return null;
        }
        [$request, $client] = $found;

        $session = $endUser->session;
        if ($session !== null && ! $this->connections->allows($client, $session->connection)) {
            return new DeviceSignInRequired($client->id, $request->userCode->value);
        }

        $now = $this->clock->now();
        $api = $request->audience === null ? null : $this->resourceServers->findByIdentifier($request->audience);
        $noPermission = $allow
            && $api !== null
            && $api->enforcePolicies
            && $this->roles->permissionsHeld($endUser->userId, $api->id)->isEmpty();

        if (! $allow || $noPermission) {
            $request->deny($endUser->userId, $now);
            $this->store->save($request);

            return new DeviceDecided(false, $noPermission);
        }

        $given = $this->consents->find($endUser->userId, $client->id, $api?->id);
        $this->consents->save($given?->widenedBy($request->scope, $now) ?? UserConsent::give(
            $endUser->userId,
            $client->id,
            $api?->id,
            $request->scope,
            $now,
        ));
        // The device holds no session here: nothing to tell it about when the browser signs out.
        $request->approve($endUser->userId, $endUser->authentication()->withoutSession(), $now);
        $this->store->save($request);

        return new DeviceDecided(true);
    }
}
