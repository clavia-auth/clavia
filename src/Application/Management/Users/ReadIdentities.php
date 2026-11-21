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
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * `GET /api/v1/users/{user_id}/identities`: the accounts at external providers linked to
 * this one — each a way in.
 */
final readonly class ReadIdentities
{
    public function __construct(
        private UserRepository $users,
        private ExternalIdentityRepository $identities,
    ) {
    }

    /**
     * @return list<ExternalIdentity> By provider, then subject.
     *
     * @throws NotFound
     */
    public function __invoke(UserId $userId): array
    {
        $this->users->find($userId) ?? throw NotFound::of('user');

        return $this->identities->ofUser($userId);
    }
}
