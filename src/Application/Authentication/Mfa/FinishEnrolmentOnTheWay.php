<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Authentication\Account\SendAccountLink;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\AuthenticationLevel;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Language;

/**
 * Raise the session of someone who has just confirmed their first authenticator app on the
 * way to a request requiring more than one factor (docs/design/mfa-policies.md §5.3).
 *
 * Confirming the app's first code proves the factor at that moment: the session gains `otp`
 * and `mfa` ({@see Sessions::stepUp()}), so the person goes on without typing a second code.
 * Only on the way — a live login state — for a verified address, and only once: a session that
 * already has more than one factor is left as it is. The owner is mailed a notice: if someone
 * else enrolled first, it is the one signal they get.
 */
final readonly class FinishEnrolmentOnTheWay
{
    public function __construct(
        private LoginStateStore $loginStates,
        private Sessions $sessions,
        private UserRepository $users,
        private SendAccountLink $mail,
    ) {
    }

    /**
     * @param list<AuthenticationMethod> $added    What the enrolled factor adds to `amr`.
     * @param Language|null              $language The page's language: what the owner's notice is in.
     *
     * @return non-empty-string|null The raised session's new identifier; null when nothing was raised.
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $sessionId,
        #[\SensitiveParameter] ?string $loginState,
        array $added,
        ?Language $language = null,
    ): ?string {
        if ($loginState === null || $loginState === '' || $this->loginStates->get($loginState) === null) {
            return null;
        }
        $session = $this->sessions->resolve($sessionId);
        $user = $session === null ? null : $this->users->find($session->userId);
        if (
            $session === null
            || $user === null
            || ! $user->isEmailVerified()
            || AuthenticationLevel::of($session->methods) !== null
        ) {
            return null;
        }

        $raised = $this->sessions->stepUp($sessionId, $session->sid, $added);
        if ($raised !== null) {
            $this->mail->secondFactorEnrolled($user->email, $language);
        }

        return $raised;
    }
}
