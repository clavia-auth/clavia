<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Identity\AssertedIdentity;
use Clavia\Domain\Identity\ExternalIdentity;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\RandomSource;

/**
 * The account an external identity signs in as — linking or creating one when needed.
 *
 * The order of the checks is the security property:
 *
 * 1. **A linked `(provider, subject)` wins**, whatever address the provider reports now:
 *    the link survives an address change at the provider, and a new address there
 *    reaches nothing here.
 * 2. **An address the provider does not vouch for links nothing and creates nothing.**
 *    Most providers let anyone register any address; an unverified one is a claim.
 *    Creating an account from it would also squat the address, keeping its real owner
 *    from ever registering it.
 * 3. **A verified address matching exactly one account links to it**, when the deployment
 *    allows it (`CLAVIA_SOCIAL_AUTO_LINK`); that account's address becomes verified,
 *    since the provider just proved it. Addresses are compared ignoring case, and two
 *    accounts matching is no answer: nothing is linked.
 * 4. **Otherwise a new account is created**: password-less, its address verified.
 *
 * A first sign-in racing with itself is settled by the storage's uniqueness: the loser
 * finds what the winner linked or created, and resolves again.
 */
final readonly class ResolveExternalAccount
{
    public function __construct(
        private UserRepository $users,
        private ExternalIdentityRepository $identities,
        private TransactionManager $transactions,
        private RandomSource $random,
        private Clock $clock,
        private bool $autoLink,
    ) {
    }

    public function __invoke(AssertedIdentity $asserted): User|ExternalSignInFailure
    {
        try {
            return $this->resolve($asserted);
        } catch (AlreadyExists) {
            // Another request linked this subject, or registered this address, first.
            return $this->resolve($asserted);
        }
    }

    private function resolve(AssertedIdentity $asserted): User|ExternalSignInFailure
    {
        $linked = $this->identities->find($asserted->provider, $asserted->subject);
        if ($linked !== null) {
            $user = $this->users->find($linked->userId);

            return $user !== null && $user->isActive() ? $user : ExternalSignInFailure::AccountDisabled;
        }

        $email = $asserted->verifiedEmail();
        if ($email === null) {
            return ExternalSignInFailure::NoVerifiedEmail;
        }

        $matches = $this->users->matchingEmail($email);
        if (count($matches) > 1 || ($matches !== [] && ! $this->autoLink)) {
            return ExternalSignInFailure::AddressAlreadyUsed;
        }
        if ($matches !== [] && ! $matches[0]->isActive()) {
            return ExternalSignInFailure::AccountDisabled;
        }

        return $this->transactions->transactional(function () use ($asserted, $email, $matches): User {
            $now = $this->clock->now();
            $user = $matches[0] ?? User::registerFromProvider(UserId::generate($this->random), $email, $now);
            if (! $user->isEmailVerified()) {
                $user->recordEmailVerification(true, $now);
            }
            $this->users->save($user);
            $this->identities->add(ExternalIdentity::link($asserted, $user->id, $now));

            return $user;
        });
    }
}
