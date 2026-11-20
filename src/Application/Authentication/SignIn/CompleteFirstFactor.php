<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * What follows a first factor, however it was satisfied — a password, an external
 * provider: a session, or, for an account with a confirmed second factor, a challenge.
 *
 * One door, so that no way of signing in can skip the second factor someone turned on.
 * The caller has already authenticated the person and validated `$nextUrl` as a
 * {@see \Clavia\Domain\Authentication\LocalPath}.
 */
final readonly class CompleteFirstFactor
{
    /**
     * @param positive-int $challengeLifetimeSeconds How long the second step may take.
     */
    public function __construct(
        private Sessions $sessions,
        private MfaFactorRepository $factors,
        private MfaChallengeStore $challenges,
        private SecretGenerator $secrets,
        private int $challengeLifetimeSeconds,
    ) {
    }

    /**
     * @param list<AuthenticationMethod> $firstFactor How the person was authenticated so far.
     * @param string|null                $replacing   The session identifier the browser presented, if any.
     */
    public function __invoke(
        UserId $userId,
        array $firstFactor,
        string $nextUrl,
        ?ClientId $clientId,
        #[\SensitiveParameter] ?string $replacing,
    ): SignedIn|SecondFactorRequired {
        if ($this->factors->find($userId)?->isConfirmed() === true) {
            $handle = $this->secrets->token();
            $this->challenges->open(
                $handle,
                new MfaChallenge($userId, $nextUrl, $clientId, $firstFactor),
                $this->challengeLifetimeSeconds,
            );

            return new SecondFactorRequired($handle);
        }

        return new SignedIn($this->sessions->establish($userId, $firstFactor, $replacing), $nextUrl);
    }
}
