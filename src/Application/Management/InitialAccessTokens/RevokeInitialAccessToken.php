<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\InitialAccessTokens;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\Registration\Event\InitialAccessTokenRevoked;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Clock;

/**
 * `DELETE /api/v1/initial-access-tokens/{id}`: stop a token at once. The clients it registered
 * keep working; revoking it again changes nothing, and records nothing.
 */
final readonly class RevokeInitialAccessToken
{
    public function __construct(
        private InitialAccessTokenRepository $tokens,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     */
    public function __invoke(InitialAccessTokenId $id): void
    {
        $token = $this->tokens->find($id) ?? throw NotFound::of('initial access token');
        if ($token->revokedAt !== null) {
            return;
        }

        $revoked = $token->revoke($this->clock->now());
        $this->tokens->save($revoked);
        $this->events->dispatch(new InitialAccessTokenRevoked($revoked));
    }
}
