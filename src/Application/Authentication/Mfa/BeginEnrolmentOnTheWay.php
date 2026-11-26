<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\AuthenticationLevel;
use Clavia\Domain\Authentication\AuthenticationRequirement;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\OAuth2\UiLocales;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Send a signed-in person with no second factor to set one up, because a request requires
 * more than one (docs/design/mfa-policies.md §5.3). The request is held behind a login state,
 * which the enrolment page carries and comes back to.
 *
 * Trust on first use: whoever holds the password of an account that has no second factor can
 * enrol their own. So only an account whose address is verified may enrol on the way — that
 * address is where the notice of the enrolment goes ({@see FinishEnrolmentOnTheWay}).
 */
final readonly class BeginEnrolmentOnTheWay
{
    /**
     * @param PasskeyRepository|null $passkeys Null when passkeys are off.
     */
    public function __construct(
        private UserRepository $users,
        private MfaFactorRepository $factors,
        private ?PasskeyRepository $passkeys,
        private LoginStateStore $loginStates,
        private SecretGenerator $secrets,
    ) {
    }

    /**
     * @param string         $nextUrl   The request to resume: a local path.
     * @param UiLocales|null $uiLocales The languages the request asked its pages in, for the enrolment pages.
     *
     * @return non-empty-string|null The login state's handle; null when this person may not enrol on the
     *                               way: an enrolled factor would be enough, or the address is unverified,
     *                               or an authenticator app could not meet the requirement.
     */
    public function __invoke(
        Session $session,
        AuthenticationRequirement $requirement,
        string $nextUrl,
        ?ClientId $clientId,
        ?UiLocales $uiLocales = null,
    ): ?string {
        if (! $requirement->accepts(AuthenticationLevel::Mfa)) {
            return null;
        }
        $user = $this->users->find($session->userId);
        if ($user === null || ! $user->isActive() || ! $user->isEmailVerified()) {
            return null;
        }
        $hasFactor = ($this->factors->find($user->id)?->isConfirmed() ?? false)
            || ($this->passkeys?->countOf($user->id) ?? 0) > 0;
        if ($hasFactor) {
            return null;
        }

        $handle = $this->secrets->token();
        $this->loginStates->put($handle, new LoginState($nextUrl, $clientId, $uiLocales));

        return $handle;
    }
}
