<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

use Clavia\Application\Authentication\EndUser;
use Clavia\Application\Port\ConsentStateStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;

/**
 * The request a consent handle stands for — if it is still there, if it is the signed-in
 * person's to decide, and if what it names still exists.
 *
 * Every other case is the same answer, "this request has expired": a handle somebody else
 * was given, an application or an API deleted in the meantime. There is nothing anyone
 * could do differently for one than for another, and telling them apart would tell a
 * stranger holding a handle whose it is.
 */
final readonly class HeldConsents
{
    public function __construct(
        private ConsentStateStore $states,
        private UserRepository $users,
        private ClientRepository $clients,
        private ResourceServerRepository $resourceServers,
    ) {
    }

    public function find(#[\SensitiveParameter] string $handle, EndUser $endUser): ?HeldConsent
    {
        $pending = $handle === '' ? null : $this->states->find($handle);
        if ($pending === null || ! $pending->userId->equals($endUser->userId)) {
            return null;
        }

        $user = $this->users->find($pending->userId);
        $client = $this->clients->find($pending->clientId);
        $api = $pending->resourceServerId === null ? null : $this->resourceServers->find($pending->resourceServerId);
        if ($user === null || $client === null || ($pending->resourceServerId !== null && $api === null)) {
            return null;
        }

        return new HeldConsent($pending, $user, $client, $api);
    }

    /**
     * Take the request off hold: true for the one caller that did, false for any other
     * racing with it.
     */
    public function release(#[\SensitiveParameter] string $handle): bool
    {
        return $this->states->claim($handle) !== null;
    }
}
