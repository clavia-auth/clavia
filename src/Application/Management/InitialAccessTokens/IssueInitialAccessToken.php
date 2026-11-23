<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\InitialAccessTokens;

use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\Registration\Event\InitialAccessTokenIssued;
use Clavia\Domain\Client\Registration\InitialAccessToken;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /api/v1/initial-access-tokens` and `clients:registration-token`: issue a token that lets
 * software register clients (RFC 7591 §3). The secret is returned once and stored as its digest.
 */
final readonly class IssueInitialAccessToken
{
    public function __construct(
        private InitialAccessTokenRepository $tokens,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws InvalidValue When the description, the lifetime or the number of uses is out of bounds.
     */
    public function __invoke(NewInitialAccessToken $new): IssuedInitialAccessToken
    {
        $secret = $this->secrets->token();
        $token = InitialAccessToken::issue(
            InitialAccessTokenId::generate($this->random),
            Digest::of($secret),
            $new->description,
            $this->clock->now(),
            $new->lifetimeSeconds,
            $new->maxUses,
        );
        $this->tokens->add($token);
        $this->events->dispatch(new InitialAccessTokenIssued($token));

        return new IssuedInitialAccessToken($token, $secret);
    }
}
