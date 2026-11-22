<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\LoginPage;

use Clavia\Application\Authentication\External\ExternalProviderOption;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;

/**
 * What the login page has to show, and where its form may lead.
 *
 * It offers exactly the connections the application behind the handle may use
 * ({@see ConnectionAccess}): a password form when it signs people in from a pool, an email
 * form when it signs them in by code or link, a link for each external connection. No
 * handle — a page reached directly — offers every usable one.
 */
final readonly class DescribeLoginPage
{
    public function __construct(
        private LoginStateStore $loginStates,
        private ClientRepository $clients,
        private ResolveEndUser $resolveEndUser,
        private UserRepository $users,
        private ConnectionAccess $access,
        private bool $passkeysEnabled = false,
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

            return new LoginPage(
                $user?->email,
                [],
                $user === null ? $this->methods(null) : SignInMethods::none(),
            );
        }

        return new LoginPage(null, $this->formOrigins($loginState), $this->methods($loginState));
    }

    /**
     * The ways in the form offers for the handle's application — or every usable one
     * without a handle.
     */
    public function methods(#[\SensitiveParameter] ?string $loginState): SignInMethods
    {
        $password = false;
        $email = false;
        $providers = [];
        $client = $this->client($loginState);
        foreach ($this->access->available($client) as $usable) {
            if ($usable->connection->isDatabase()) {
                $password = true;
            } elseif ($usable->connection->isPasswordless()) {
                $email = true;
            } elseif ($usable->provider !== null) {
                $providers[] = new ExternalProviderOption(
                    $usable->connection->name->value,
                    $usable->connection->displayName,
                );
            }
        }

        $pool = $this->access->signUpPool($client);
        $mail = $this->access->canSendMail();

        return new SignInMethods(
            $password,
            $email,
            $providers,
            // Sign-up needs mail only when the new account must prove its address first.
            $pool !== null && ($mail || ! $pool->requiresVerifiedEmail),
            // A reset link is mailed: no mail, no "forgot your password".
            $password && $mail,
            // A passkey signs into the account it belongs to, through that account's connection:
            // offered wherever the application lets anybody in, and checked against it at the end.
            $this->passkeysEnabled && ($password || $email || $providers !== []),
        );
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
        return $this->client($loginState)?->redirectOrigins() ?? [];
    }

    /** The application behind a login page's handle, if the handle names one. */
    private function client(#[\SensitiveParameter] ?string $loginState): ?Client
    {
        if ($loginState === null || $loginState === '') {
            return null;
        }

        $clientId = $this->loginStates->get($loginState)?->clientId;

        return $clientId === null ? null : $this->clients->find($clientId);
    }
}
