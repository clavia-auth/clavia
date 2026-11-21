<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Application\Authentication\Passwordless;

use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use Clavia\Domain\Authentication\PasswordlessMode;
use Clavia\Domain\Client\ClientRepository;

/**
 * What the code page or the link's confirmation page shows, before anything is spent.
 */
final readonly class DescribePasswordlessChallenge
{
    public function __construct(
        private PasswordlessChallengeStore $challenges,
        private ClientRepository $clients,
    ) {
    }

    /**
     * @param string|null $handle The code challenge's cookie, or the link's token.
     *
     * @return PasswordlessPrompt|null Null when the handle names no pending challenge of that mode.
     */
    public function __invoke(#[\SensitiveParameter] ?string $handle, PasswordlessMode $mode): ?PasswordlessPrompt
    {
        $challenge = $handle === null || $handle === '' ? null : $this->challenges->find($handle);

        return $challenge === null || $challenge->mode !== $mode ? null : $this->prompt($challenge);
    }

    public function prompt(PasswordlessChallenge $challenge): PasswordlessPrompt
    {
        $client = $challenge->clientId === null ? null : $this->clients->find($challenge->clientId);

        return new PasswordlessPrompt($challenge->email, $client?->redirectOrigins() ?? []);
    }
}
