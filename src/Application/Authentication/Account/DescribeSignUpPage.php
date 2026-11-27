<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\ClientRepository;

/**
 * What the sign-up page shows for the login page's handle: whether the application takes
 * sign-ups at all, whether the new account must prove its address first, and where the
 * form may lead.
 */
final readonly class DescribeSignUpPage
{
    public function __construct(
        private ConnectionAccess $access,
        private LoginStateStore $loginStates,
        private ClientRepository $clients,
        private DescribeLoginPage $loginPage,
    ) {
    }

    public function __invoke(#[\SensitiveParameter] ?string $loginState): SignUpPage
    {
        $clientId = $loginState === null || $loginState === '' ? null : $this->loginStates->get($loginState)?->clientId;
        $pool = $this->access->signUpPool($clientId === null ? null : $this->clients->find($clientId));
        if ($pool === null || ($pool->requiresVerifiedEmail && ! $this->access->canSendMail())) {
            return new SignUpPage(false, false, []);
        }

        return new SignUpPage(true, $pool->requiresVerifiedEmail, $this->loginPage->formOrigins($loginState));
    }

    /** Whether the page names a held request that is gone: then it offers no form. */
    public function requestHasExpired(#[\SensitiveParameter] ?string $loginState): bool
    {
        return $this->loginPage->requestHasExpired($loginState);
    }
}
