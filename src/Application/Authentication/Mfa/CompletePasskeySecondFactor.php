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
use Clavia\Application\Port\PasskeyRejected;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\PasskeyCounterRegressed;
use Clavia\Domain\Authentication\Event\SignInRefusal;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Authentication\Passkey\CounterRegressed;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Finish a sign-in with a passkey as its second factor (docs/design/passkeys.md §6.3).
 *
 * The same contract as {@see CompleteSecondFactor}, for the other kind of answer:
 *
 * - the ceremony is claimed first, so it answers once, and it must be the second factor of this
 *   challenge, for this account, still live;
 * - the passkey must be the account's own, the response must verify against it (user presence
 *   is enough: the password came first), and its counter must have grown, or be zero throughout.
 *   The use is recorded by a conditional write, so two sign-ins racing on one counter cannot both
 *   pass;
 * - any failure counts against the challenge and the throttle, exactly as a wrong code does. A
 *   counter that went back is audited for what it is, and the passkey stays, for its holder or an
 *   operator to look at;
 * - success adds the passkey's methods to `amr` (`hwk` or `swk`, and `user` when nobody was
 *   verified), then `mfa`.
 */
final readonly class CompletePasskeySecondFactor
{
    /**
     * @param positive-int $maxAttempts `CLAVIA_MFA_MAX_ATTEMPTS`, shared with codes.
     */
    public function __construct(
        private MfaChallengeStore $challenges,
        private WebAuthnChallengeStore $ceremonies,
        private UserRepository $users,
        private PasskeyRepository $passkeys,
        private PasskeyVerifier $verifier,
        private LoginThrottle $throttle,
        private Sessions $sessions,
        private Clock $clock,
        private RelyingParty $relyingParty,
        private int $maxAttempts,
        private DomainEvents $events,
    ) {
    }

    public function __invoke(PasskeySecondFactorAttempt $attempt): SecondFactorOutcome
    {
        $ceremony = $attempt->ceremony === '' ? null : $this->ceremonies->claim($attempt->ceremony);
        $challenge = $attempt->challenge === '' ? null : $this->challenges->find($attempt->challenge);
        if ($challenge === null) {
            return new ChallengeGone();
        }

        $user = $this->users->find($challenge->userId);
        $refusal = SignInRefusal::WrongSecondFactor;
        $passkey = null;
        $methods = null;
        $throttled = $user !== null && $this->throttle->isThrottled($user->email, $attempt->clientAddress);
        if ($user !== null && $user->isActive() && ! $throttled) {
            [$refusal, $passkey, $methods] = $this->verify($user, $challenge, $attempt, $ceremony);
        }

        if ($user === null || $methods === null) {
            $this->throttle->recordFailure($user?->email ?? '', $attempt->clientAddress);
            $this->events->dispatch(new SignInRefused(
                $passkey?->authenticationMethods(true)[0],
                $refusal,
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

        return new SignedIn(
            $this->sessions->establish(
                $challenge->userId,
                AuthenticationMethod::combined($challenge->firstFactor, $methods),
                $challenge->connection,
                $attempt->currentSessionId,
            ),
            $challenge->nextUrl,
        );
    }

    /**
     * @return array{SignInRefusal, Passkey|null, list<AuthenticationMethod>|null} Why it was refused, the
     *         passkey it was about, and — when it was not — what it adds to `amr`.
     */
    private function verify(
        User $user,
        MfaChallenge $challenge,
        PasskeySecondFactorAttempt $attempt,
        ?WebAuthnChallenge $ceremony,
    ): array {
        $now = $this->clock->now();
        if (
            $ceremony === null
            || ! $ceremony->isFor(WebAuthnPurpose::SecondFactor, $attempt->challenge)
            || $ceremony->userId === null
            || ! $ceremony->userId->equals($user->id)
            || $ceremony->isExpired($now)
        ) {
            return [SignInRefusal::WrongSecondFactor, null, null];
        }

        try {
            $passkey = $this->passkeys->ofCredentialId($this->verifier->credentialIdOf($attempt->response));
        } catch (PasskeyRejected) {
            return [SignInRefusal::WrongSecondFactor, null, null];
        }
        if ($passkey === null || ! $passkey->userId->equals($user->id)) {
            return [SignInRefusal::UnknownPasskey, null, null];
        }

        try {
            $verified = $this->verifier->verifyAssertion($attempt->response, $ceremony, $this->relyingParty, $passkey);
        } catch (PasskeyRejected) {
            return [SignInRefusal::WrongSecondFactor, $passkey, null];
        }

        $previous = $passkey->signCount;
        try {
            $passkey->recordUse($verified->signCount, $verified->backedUp, $now);
        } catch (CounterRegressed) {
            $this->events->dispatch(new PasskeyCounterRegressed(
                $passkey->userId,
                $passkey->id,
                $passkey->name,
                $previous,
                $verified->signCount,
            ));

            return [SignInRefusal::PasskeyCounterRegressed, $passkey, null];
        } catch (InvalidValue) {
            return [SignInRefusal::WrongSecondFactor, $passkey, null];
        }
        // Another sign-in moved the counter first: refused as a regression is, but nothing was cloned.
        if (! $this->passkeys->recordUse($passkey, $previous)) {
            return [SignInRefusal::WrongSecondFactor, $passkey, null];
        }

        return [SignInRefusal::WrongSecondFactor, $passkey, $passkey->authenticationMethods($verified->userVerified)];
    }
}
