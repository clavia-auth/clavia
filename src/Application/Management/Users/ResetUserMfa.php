<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Management\NotFound;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * `DELETE /api/v1/users/{user_id}/mfa`: the way back for someone who lost both their
 * authenticator and their recovery codes. Every factor and code goes; the next sign-in
 * is by password alone. Idempotent: the operator asked for it to be off, and it is.
 */
final readonly class ResetUserMfa
{
    public function __construct(
        private UserRepository $users,
        private DisableMfa $disable,
    ) {
    }

    /**
     * @throws NotFound
     */
    public function __invoke(UserId $id): void
    {
        $this->users->find($id) ?? throw NotFound::of('user');
        ($this->disable)($id);
    }
}
