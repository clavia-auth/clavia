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
use Clavia\Domain\Authentication\Event\PasskeyCounterRegressed;
use Clavia\Domain\Authentication\Passkey\CounterRegressed;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Answer a sign-in or second-factor ceremony with a passkey (docs/design/passkeys.md §6.2, §6.3):
 * the part the two share, after each has checked that the ceremony is the right one.
 *
 * 1. The passkey is found by the response's credential id; when the account is known, it must
 *    be that account's.
 * 2. The response is verified against it. The verifier holds the ceremony to what its purpose
 *    demands: user verification at sign-in, the owner named by the user handle when the account
 *    was not known first.
 * 3. Its counter must have grown, or be zero throughout. A counter that went back is audited for
 *    what it is (`PasskeyCounterRegressed`, dispatched here, outside any transaction, so it
 *    survives the refusal), and the passkey stays for its holder or an operator to look at.
 * 4. The use is a conditional write: two answers racing on one counter cannot both pass.
 */
final readonly class UsePasskey
{
    public function __construct(
        private PasskeyRepository $passkeys,
        private PasskeyVerifier $verifier,
        private RelyingParty $relyingParty,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param UserId|null $account The account the ceremony is for, when it is known before.
     */
    public function __invoke(
        WebAuthnChallenge $ceremony,
        string $response,
        ?UserId $account,
    ): PasskeyUsed|PasskeyNotUsed {
        try {
            $passkey = $this->passkeys->ofCredentialId($this->verifier->credentialIdOf($response));
        } catch (PasskeyRejected) {
            return new PasskeyNotUsed(PasskeyRefusal::Rejected);
        }
        if ($passkey === null || ($account !== null && ! $passkey->userId->equals($account))) {
            return new PasskeyNotUsed(PasskeyRefusal::Unknown);
        }

        try {
            $verified = $this->verifier->verifyAssertion($response, $ceremony, $this->relyingParty, $passkey);
        } catch (PasskeyRejected) {
            return new PasskeyNotUsed(PasskeyRefusal::Rejected, $passkey);
        }

        $previous = $passkey->signCount;
        try {
            $passkey->recordUse($verified->signCount, $verified->backedUp, $this->clock->now());
        } catch (CounterRegressed) {
            $this->events->dispatch(new PasskeyCounterRegressed(
                $passkey->userId,
                $passkey->id,
                $passkey->name,
                $previous,
                $verified->signCount,
            ));

            return new PasskeyNotUsed(PasskeyRefusal::CounterRegressed, $passkey);
        } catch (InvalidValue) {
            return new PasskeyNotUsed(PasskeyRefusal::Rejected, $passkey);
        }
        if (! $this->passkeys->recordUse($passkey, $previous)) {
            return new PasskeyNotUsed(PasskeyRefusal::Raced, $passkey);
        }

        return new PasskeyUsed($passkey, $verified->userVerified);
    }
}
