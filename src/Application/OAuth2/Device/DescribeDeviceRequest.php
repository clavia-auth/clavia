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
use Clavia\Application\OAuth2\Consent\ScopeDescriptions;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\ScopeSet;

/**
 * `GET /auth/device?user_code=…`: what the person is asked to allow.
 */
final readonly class DescribeDeviceRequest
{
    /**
     * @param ScopeSet $supportedScopes The OIDC scopes this server issues.
     */
    public function __construct(
        private PendingDeviceRequests $pending,
        private UserRepository $users,
        private ResourceServerRepository $resourceServers,
        private ScopeSet $supportedScopes,
    ) {
    }

    /**
     * @return DeviceReview|null Null when the code stands for nothing to decide.
     */
    public function __invoke(string $typed, EndUser $endUser): ?DeviceReview
    {
        $found = $this->pending->find($typed);
        $user = $this->users->find($endUser->userId);
        if ($found === null || $user === null) {
            return null;
        }
        [$request, $client] = $found;
        $api = $request->audience === null ? null : $this->resourceServers->findByIdentifier($request->audience);

        return new DeviceReview(
            $request->userCode->value,
            $client->name === '' ? $client->id->value : $client->name,
            $user->email,
            ScopeDescriptions::oidc($request->scope, $this->supportedScopes),
            $api === null ? null : ScopeDescriptions::api($api, $request->scope),
        );
    }
}
