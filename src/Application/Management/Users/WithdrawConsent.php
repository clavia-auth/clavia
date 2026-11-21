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
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * `DELETE /api/v1/users/{user_id}/consents/{client_id}`: withdraw everything the person
 * allowed one application, on every API.
 *
 * The application's next authorization request asks again. Tokens it already holds run
 * to their own expiry: a consent governs what may be asked for, and revoking what was
 * already issued is a different operation. Idempotent: nothing to withdraw is still
 * "withdrawn".
 */
final readonly class WithdrawConsent
{
    public function __construct(
        private UserRepository $users,
        private ConsentRepository $consents,
    ) {
    }

    /**
     * @throws NotFound When the user does not exist.
     */
    public function __invoke(UserId $userId, ClientId $clientId): void
    {
        $this->users->find($userId) ?? throw NotFound::of('user');
        $this->consents->withdraw($userId, $clientId);
    }
}
