<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\ResourceServer\ResourceServerRepository;

/**
 * `GET /api/v1/users/{user_id}/consents`: every application the person allowed to act as
 * them, and what they allowed it.
 *
 * Only what they were actually asked: a first-party application that did without the
 * consent screen has no record here, because there was no decision to record.
 */
final readonly class ReadConsents
{
    public function __construct(
        private UserRepository $users,
        private ConsentRepository $consents,
        private ClientRepository $clients,
        private ResourceServerRepository $resourceServers,
    ) {
    }

    /**
     * @return list<DescribedConsent> Oldest first.
     *
     * @throws NotFound
     */
    public function __invoke(UserId $userId): array
    {
        $this->users->find($userId) ?? throw NotFound::of('user');

        $described = [];
        foreach ($this->consents->ofUser($userId) as $consent) {
            // The foreign keys make both exist; a row read while one is being deleted is skipped.
            $client = $this->clients->find($consent->clientId);
            $api = $consent->resourceServerId === null
                ? null
                : $this->resourceServers->find($consent->resourceServerId);
            if ($client === null || ($consent->resourceServerId !== null && $api === null)) {
                continue;
            }
            $described[] = new DescribedConsent($consent, $client, $api?->identifier);
        }

        return $described;
    }
}
