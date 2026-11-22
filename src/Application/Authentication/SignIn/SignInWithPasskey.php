<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

use Clavia\Application\Authentication\LoginThrottle;
use Clavia\Application\Authentication\Passkey\PasskeyRefusal;
use Clavia\Application\Authentication\Passkey\PasskeyUsed;
use Clavia\Application\Authentication\Passkey\UsePasskey;
use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\SignInRefusal;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\Clock;

/**
 * Sign in with a passkey, the account named by the passkey itself (docs/design/passkeys.md
 * §6.2): a first factor, ending at {@see CompleteFirstFactor} like every other.
 *
 * 1. The ceremony is claimed first, and must be this page's sign-in ceremony, still live.
 * 2. The client address must not be throttled: there is no account to count against until the
 *    passkey names one.
 * 3. The passkey answers it ({@see UsePasskey}): found, its owner named by the user handle, the
 *    person verified, the counter grown.
 * 4. The account must be active, and its connection one the application lets people in through.
 * 5. With `CLAVIA_PASSKEY_SATISFIES_MFA` on, a passkey that verified the person is multi-factor by
 *    itself (`amr` `hwk` or `swk`, then `mfa`), and the session is established; off, the second
 *    factor follows as after a password.
 *
 * Every failure is {@see CredentialsRejected}: the same answer as a wrong password, whatever it
 * was. The trail keeps the reason.
 */
final readonly class SignInWithPasskey
{
    public function __construct(
        private WebAuthnChallengeStore $ceremonies,
        private UsePasskey $usePasskey,
        private UserRepository $users,
        private LoginStateStore $loginStates,
        private ClientRepository $clients,
        private ConnectionAccess $access,
        private LoginThrottle $throttle,
        private Sessions $sessions,
        private CompleteFirstFactor $completeFirstFactor,
        private Clock $clock,
        private DomainEvents $events,
        private bool $satisfiesMfa,
    ) {
    }

    public function __invoke(PasskeySignIn $attempt): SignedIn|SecondFactorRequired|CredentialsRejected
    {
        $loginState = $attempt->loginState === null || $attempt->loginState === '' ? null : $attempt->loginState;
        $pending = $loginState === null ? null : $this->loginStates->get($loginState);
        $clientId = $pending?->clientId;

        // Claimed before anything is checked: a ceremony answers once, rightly or not.
        $ceremony = $attempt->ceremony === '' ? null : $this->ceremonies->claim($attempt->ceremony);
        if (
            $ceremony === null
            || ! $ceremony->isFor(WebAuthnPurpose::SignIn, $loginState ?? $attempt->ceremony)
            || $ceremony->isExpired($this->clock->now())
        ) {
            return $this->refused($attempt, $clientId, SignInRefusal::Expired);
        }
        if ($this->throttle->isAddressThrottled($attempt->clientAddress)) {
            return $this->refused($attempt, $clientId, SignInRefusal::Throttled);
        }

        $used = ($this->usePasskey)($ceremony, $attempt->response, null);
        if (! $used instanceof PasskeyUsed) {
            return $this->refused($attempt, $clientId, match ($used->reason) {
                PasskeyRefusal::Unknown => SignInRefusal::UnknownPasskey,
                PasskeyRefusal::CounterRegressed => SignInRefusal::PasskeyCounterRegressed,
                PasskeyRefusal::Rejected, PasskeyRefusal::Raced => SignInRefusal::InvalidPasskey,
            }, $used->passkey);
        }

        $user = $this->users->find($used->passkey->userId);
        if ($user === null || ! $user->isActive()) {
            return $this->refused($attempt, $clientId, SignInRefusal::AccountDisabled, $used->passkey);
        }
        $client = $clientId === null ? null : $this->clients->find($clientId);
        if (! $this->access->allows($client, $user->connection)) {
            return $this->refused($attempt, $clientId, SignInRefusal::NotAvailable, $used->passkey);
        }

        $this->throttle->resetAddress($attempt->clientAddress);
        if ($loginState !== null) {
            $this->loginStates->forget($loginState);
        }
        // Re-validated even though it came from this server's own store.
        $nextUrl = LocalPath::orDefault($pending?->nextUrl)->value;

        if ($this->satisfiesMfa && $used->userVerified) {
            return new SignedIn(
                $this->sessions->establish(
                    $user->id,
                    AuthenticationMethod::combined([], $used->methods()),
                    $user->connection,
                    $attempt->currentSessionId,
                ),
                $nextUrl,
            );
        }

        return ($this->completeFirstFactor)(
            $user->id,
            $used->methods(),
            $user->connection,
            $nextUrl,
            $clientId,
            $attempt->currentSessionId,
        );
    }

    /** A refused passkey, for the trail: the account it named, when it named one, and why. */
    private function refused(
        PasskeySignIn $attempt,
        ?ClientId $clientId,
        SignInRefusal $reason,
        ?Passkey $passkey = null,
    ): CredentialsRejected {
        if ($reason !== SignInRefusal::Throttled) {
            $this->throttle->recordAddressFailure($attempt->clientAddress);
        }
        $this->events->dispatch(new SignInRefused(
            $passkey?->authenticationMethods(true)[0],
            $reason,
            $passkey?->userId,
            clientId: $clientId,
        ));

        return new CredentialsRejected();
    }
}
