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
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * `GET /api/v1/users/{user_id}/passkeys`: the account's passkeys, as an operator sees them —
 * never a credential id or a key.
 */
final readonly class ReadUserPasskeys
{
    public function __construct(
        private UserRepository $users,
        private PasskeyRepository $passkeys,
    ) {
    }

    /**
     * @return list<Passkey> Oldest first.
     *
     * @throws NotFound
     */
    public function __invoke(UserId $userId): array
    {
        $this->users->find($userId) ?? throw NotFound::of('user');

        return $this->passkeys->ofUser($userId);
    }
}
