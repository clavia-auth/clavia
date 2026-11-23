<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\SignInRefusal;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;

/**
 * Finish a sign-in with its second factor: a TOTP code, or failing that a recovery
 * code, and then — only then — a session.
 *
 * - The account is re-checked, not trusted from the password step: one deactivated in
 *   the last few minutes does not complete a sign-in.
 * - A TOTP code is checked under the factor's row lock and its step spent in the same
 *   transaction; a recovery code is spent by a conditional write. Either way, a code
 *   works once.
 * - A wrong answer counts against the challenge (destroyed at the limit, see
 *   {@see MfaChallengeStore::recordFailure()}) and against the throttle, per account and
 *   per address — so guessing across many challenges from one place trips the same
 *   limit as guessing passwords does. A throttled subject is refused without the code
 *   being looked at.
 * - The session's `amr` is the first factor's methods, then `otp` for a TOTP code, then
 *   `mfa` (RFC 8176); a recovery code adds `mfa` alone — it is no one-time password
 *   from a device.
 * - A **step-up** challenge raises the browser's session instead of starting one
 *   ({@see Sessions::stepUp()}), and takes only a code that makes it meet the request: an
 *   app's code or a recovery code cannot answer a request for a passkey's level. A code of
 *   a kind that cannot answer is refused without being looked at.
 */
final readonly class CompleteSecondFactor
{
    /**
     * @param positive-int $maxAttempts
     */
    public function __construct(
        private MfaChallengeStore $challenges,
        private UserRepository $users,
        private MfaFactorRepository $factors,
        private RecoveryCodeRepository $recoveryCodes,
        private TotpSeeds $seeds,
        private LoginThrottle $throttle,
        private Sessions $sessions,
        private TransactionManager $transactions,
        private Clock $clock,
        private int $maxAttempts,
        private DomainEvents $events,
    ) {
    }

    public function __invoke(SecondFactorAttempt $attempt): SecondFactorOutcome
    {
        $challenge = $attempt->challenge === '' ? null : $this->challenges->find($attempt->challenge);
        if ($challenge === null) {
            return new ChallengeGone();
        }

        $user = $this->users->find($challenge->userId);
        $secondFactor = $user !== null && $user->isActive() ? $this->verify($user, $attempt, $challenge) : null;

        if ($user === null || $secondFactor === null) {
            $this->throttle->recordFailure($user?->email ?? '', $attempt->clientAddress);
            // The password was right — whoever is here holds it — and that is all.
            $this->events->dispatch(new SignInRefused(
                AuthenticationMethod::OneTimePassword,
                SignInRefusal::WrongSecondFactor,
                $challenge->userId,
                clientId: $challenge->clientId,
                connection: $challenge->connection,
            ));

            return $this->challenges->recordFailure($attempt->challenge, $this->maxAttempts)
                ? new SecondFactorRejected()
                : new ChallengeGone();
        }

        $this->challenges->close($attempt->challenge);
        $this->throttle->reset($user->email, $attempt->clientAddress);

        return $this->signIn($challenge, $secondFactor, $attempt);
    }

    /**
     * @return list<AuthenticationMethod>|null What the second factor adds to `amr`, or null when
     *                                         nothing was accepted.
     */
    private function verify(User $user, SecondFactorAttempt $attempt, MfaChallenge $challenge): ?array
    {
        if ($this->throttle->isThrottled($user->email, $attempt->clientAddress)) {
            return null;
        }
        $appAnswers = $challenge->isAnsweredBy(SecondFactors::APP);
        $recoveryCodeAnswers = $challenge->isAnsweredBy(SecondFactors::RECOVERY_CODE);
        if (! $appAnswers && ! $recoveryCodeAnswers) {
            return null;
        }

        $codeWorks = [$appAnswers, $recoveryCodeAnswers];

        return $this->transactions->transactional(function () use ($user, $attempt, $codeWorks): ?array {
            [$appAnswers, $recoveryCodeAnswers] = $codeWorks;
            $now = $this->clock->now();
            $factor = $appAnswers ? $this->factors->lockForVerification($user->id) : null;
            $app = $factor !== null && $factor->isConfirmed() ? $factor : null;
            if ($app !== null && $app->accept($this->seeds->open($app), $attempt->code, $now)) {
                $this->factors->save($app);

                return SecondFactors::APP;
            }

            // A recovery code answers whatever the second factor is: an authenticator app or a
            // passkey, whose loss is what the codes are for.
            return $recoveryCodeAnswers
                && $this->recoveryCodes->spend($user->id, RecoveryCode::digest($attempt->code), $now)
                ? SecondFactors::RECOVERY_CODE
                : null;
        });
    }

    /**
     * @param list<AuthenticationMethod> $secondFactor
     */
    private function signIn(
        MfaChallenge $challenge,
        array $secondFactor,
        SecondFactorAttempt $attempt,
    ): SignedIn|ChallengeGone {
        if ($challenge->stepUpOf !== null) {
            $raised = $this->sessions->stepUp($attempt->currentSessionId, $challenge->stepUpOf, $secondFactor);

            return $raised === null ? new ChallengeGone() : new SignedIn($raised, $challenge->nextUrl);
        }

        $sessionId = $this->sessions->establish(
            $challenge->userId,
            AuthenticationMethod::combined($challenge->firstFactor, $secondFactor),
            $challenge->connection,
            $attempt->currentSessionId,
        );

        return new SignedIn($sessionId, $challenge->nextUrl);
    }
}
