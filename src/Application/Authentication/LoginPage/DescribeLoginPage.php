<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\LoginPage;

use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;

/**
 * What the login page has to show, and where its form may lead.
 */
final readonly class DescribeLoginPage
{
    public function __construct(
        private LoginStateStore $loginStates,
        private ClientRepository $clients,
        private ResolveEndUser $resolveEndUser,
        private UserRepository $users,
    ) {
    }

    /**
     * @param string|null $loginState The opaque handle of the pending authorization request, if any.
     * @param string|null $sessionId  The identifier the browser's session cookie carries. Pass null
     *                                to describe the form regardless of who is signed in.
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $loginState,
        #[\SensitiveParameter] ?string $sessionId,
    ): LoginPage {
        if ($loginState === null || $loginState === '') {
            // Signed in with nothing to return to: signing in again would only land the
            // person back here. They are told who they are instead.
            $endUser = ($this->resolveEndUser)($sessionId);
            $user = $endUser === null ? null : $this->users->find($endUser->userId);

            return new LoginPage($user?->email, []);
        }

        return new LoginPage(null, $this->formOrigins($loginState));
    }

    /**
     * Where a sign-in submitted from the page for this handle may end: the origins of the
     * redirect URIs of the application the pending request is for. Empty when the handle
     * names nothing, or no application.
     *
     * @return list<string>
     */
    public function formOrigins(#[\SensitiveParameter] ?string $loginState): array
    {
        if ($loginState === null || $loginState === '') {
            return [];
        }

        $clientId = $this->loginStates->get($loginState)?->clientId;
        $client = $clientId === null ? null : $this->clients->find($clientId);

        return $client?->redirectOrigins() ?? [];
    }
}
