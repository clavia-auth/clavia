<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\AuthenticationRequirement;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\UiLocales;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Ask a signed-in person for one more factor, because a request wants more than their
 * session has (docs/design/mfa-policies.md §5.2): open a step-up challenge for the second-factor
 * page, unless nothing the person holds could answer it.
 */
final readonly class BeginStepUp
{
    /**
     * @param positive-int $challengeLifetimeSeconds How long the step may take (`CLAVIA_MFA_CHALLENGE_LIFETIME`).
     */
    public function __construct(
        private MfaChallengeStore $challenges,
        private SecondFactors $secondFactors,
        private SecretGenerator $secrets,
        private int $challengeLifetimeSeconds,
    ) {
    }

    /**
     * @param string         $nextUrl   Where the browser goes once the session is raised: a local path.
     * @param UiLocales|null $uiLocales The languages the request asked its pages in, for the step's page.
     *
     * @return non-empty-string|null The challenge's handle; null when no factor the person holds reaches
     *                               any level the requirement accepts.
     */
    public function __invoke(
        Session $session,
        AuthenticationRequirement $requirement,
        string $nextUrl,
        ?ClientId $clientId,
        ?UiLocales $uiLocales = null,
    ): ?string {
        $challenge = MfaChallenge::stepUp($session, $requirement, $nextUrl, $clientId, $uiLocales);
        if (! $this->secondFactors->offeredFor($challenge)->any()) {
            return null;
        }

        $handle = $this->secrets->token();
        $this->challenges->open($handle, $challenge, $this->challengeLifetimeSeconds);

        return $handle;
    }
}
