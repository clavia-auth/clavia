<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;

/**
 * Mail a reset link to every active account with an address, in the pools the application
 * signs people in from.
 *
 * The answer is {@see CheckYourInbox} whatever happened — an unknown address, a limit
 * reached, a mail server down — so the form says nothing about who has an account. An unknown
 * address is mailed nothing: a stranger's mailbox is not a place to send an unsolicited link.
 * An account an operator created without a password gets one too: the reset is its invitation.
 */
final readonly class RequestPasswordReset
{
    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private LoginStateStore $loginStates,
        private UserRepository $users,
        private SendAccountLink $links,
    ) {
    }

    /**
     * @param string|null $loginState    The login page's handle the form carried.
     * @param string      $clientAddress Where the request came from (`REMOTE_ADDR`).
     */
    public function __invoke(
        string $email,
        #[\SensitiveParameter] ?string $loginState,
        string $clientAddress,
    ): CheckYourInbox|ResetUnavailable|SignUpRefused {
        $loginState = $loginState === null || $loginState === '' ? null : $loginState;
        $clientId = $loginState === null ? null : $this->loginStates->get($loginState)?->clientId;
        $pools = $this->access->pools($clientId === null ? null : $this->clients->find($clientId));
        if ($pools === [] || ! $this->access->canSendMail()) {
            return new ResetUnavailable();
        }
        $email = trim($email);
        if ($email === '' || ! str_contains($email, '@')) {
            return new SignUpRefused(SignUpFailure::InvalidEmail, $email);
        }

        foreach ($pools as $pool) {
            $user = $this->users->findByEmail($pool, $email);
            if ($user !== null && $user->isActive()) {
                $this->links->reset($user, $loginState, $clientAddress);
            }
        }

        return new CheckYourInbox($email);
    }
}
