<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasskeyRejected;
use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Application\Port\TransactionManager;
use Clavia\Application\Port\VerifiedRegistration;
use Clavia\Application\Port\WebAuthnChallengeStore;
use Clavia\Domain\Authentication\Event\PasskeyRegistered;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCode;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnPurpose;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use DateTimeImmutable;

/**
 * Turn the browser's answer to a registration ceremony into a passkey (docs/design/passkeys.md
 * §6.1).
 *
 * The ceremony is claimed first, so it is spent whatever follows, and it must be a registration
 * for the session's own account, still live. The response is verified; the passkey is saved and
 * announced in one transaction, where the credential's unique constraint decides whether it was
 * registered before. A passkey that is the account's first second factor brings recovery codes
 * with it when the account holds none, as turning on an authenticator app does: they are shown
 * once, and are the way back if the device is lost.
 */
final readonly class CompletePasskeyRegistration
{
    /**
     * @param positive-int $maxPerUser        `CLAVIA_PASSKEY_MAX_PER_USER`.
     * @param positive-int $recoveryCodeCount `CLAVIA_MFA_RECOVERY_CODE_COUNT`.
     */
    public function __construct(
        private WebAuthnChallengeStore $ceremonies,
        private PasskeyVerifier $verifier,
        private PasskeyRepository $passkeys,
        private MfaFactorRepository $factors,
        private RecoveryCodeRepository $recoveryCodes,
        private TransactionManager $transactions,
        private DomainEvents $events,
        private RandomSource $random,
        private Clock $clock,
        private RelyingParty $relyingParty,
        private RecentSignIn $recentSignIn,
        private int $maxPerUser,
        private int $recoveryCodeCount,
    ) {
    }

    /**
     * @param string $handle       The ceremony's handle, from the browser's cookie.
     * @param string $responseJson The credential, as the browser's `toJSON()` wrote it.
     * @param string $name         What the person calls it; empty for a default.
     */
    public function __invoke(
        Session $session,
        #[\SensitiveParameter] string $handle,
        string $responseJson,
        string $name,
    ): PasskeyAdded|PasskeyNotAdded|SignInAgain|PasskeyLimitReached {
        // Claimed before anything is checked: a ceremony answers once, rightly or not.
        $challenge = $this->ceremonies->claim($handle);
        if (! $this->recentSignIn->allows($session)) {
            return new SignInAgain();
        }
        $now = $this->clock->now();
        if (
            $challenge === null
            || ! $challenge->isFor(WebAuthnPurpose::Registration)
            || $challenge->userId === null
            || ! $challenge->userId->equals($session->userId)
            || $challenge->isExpired($now)
        ) {
            return PasskeyNotAdded::CeremonyGone;
        }

        try {
            $passkeyName = PasskeyName::fromString(trim($name) === '' ? self::defaultName($now) : $name);
        } catch (InvalidValue) {
            return PasskeyNotAdded::InvalidName;
        }

        try {
            $verified = $this->verifier->verifyRegistration($responseJson, $challenge, $this->relyingParty);
        } catch (PasskeyRejected) {
            return PasskeyNotAdded::Rejected;
        }

        try {
            return $this->transactions->transactional(
                fn (): PasskeyAdded|PasskeyLimitReached => $this->save($session, $verified, $passkeyName, $now),
            );
        } catch (AlreadyExists) {
            // Out of the transaction, not in it: after a failed statement PostgreSQL refuses the
            // rest of it, so the refusal rolls it back and is answered here.
            return PasskeyNotAdded::AlreadyRegistered;
        }
    }

    /**
     * In the caller's transaction: the limit, the passkey, its recovery codes, the event.
     *
     * @throws AlreadyExists When the credential is registered already: the transaction is lost.
     */
    private function save(
        Session $session,
        VerifiedRegistration $verified,
        PasskeyName $passkeyName,
        DateTimeImmutable $now,
    ): PasskeyAdded|PasskeyLimitReached {
        $count = $this->passkeys->countOf($session->userId);
        if ($count >= $this->maxPerUser) {
            return new PasskeyLimitReached($this->maxPerUser);
        }
        $passkey = Passkey::register(
            PasskeyId::generate($this->random),
            $session->userId,
            $verified->credentialId,
            $verified->publicKey,
            $verified->algorithm,
            $verified->signCount,
            $verified->transports,
            $verified->aaguid,
            $verified->backupEligible,
            $verified->backedUp,
            $passkeyName,
            $now,
        );
        $this->passkeys->save($passkey);
        $codes = $this->recoveryCodesFor($session, $count === 0, $now);
        $this->events->dispatch(new PasskeyRegistered(
            $passkey->userId,
            $passkey->id,
            $passkey->name,
            $passkey->isSynced(),
            $passkey->aaguid,
        ));

        return new PasskeyAdded($passkey->name, $codes);
    }

    /** What a passkey is called when its owner does not say: when it was added. */
    private static function defaultName(DateTimeImmutable $now): string
    {
        return 'Passkey added ' . $now->format('j M Y');
    }

    /**
     * Recovery codes for a first second factor on an account that holds none.
     *
     * @return list<string>|null
     */
    private function recoveryCodesFor(Session $session, bool $firstPasskey, DateTimeImmutable $now): ?array
    {
        $hasAuthenticatorApp = $this->factors->find($session->userId)?->isConfirmed() ?? false;
        if (! $firstPasskey || $hasAuthenticatorApp || $this->recoveryCodes->unusedCount($session->userId) > 0) {
            return null;
        }
        $codes = RecoveryCode::issue($this->random, $this->recoveryCodeCount);
        $this->recoveryCodes->replaceAll($session->userId, array_map(RecoveryCode::digest(...), $codes), $now);

        return $codes;
    }
}
