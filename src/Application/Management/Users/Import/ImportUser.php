<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Import;

use Clavia\Application\Management\Users\ProfileFields;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\Event\UserCreated;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;

/**
 * Imports one account ({@see UserImport}): the line read by {@see ImportLine}, then the account made in
 * a transaction of its own, so it exists with everything it needs or not at all, and a `UserCreated`
 * announces it, in the name of whoever the audit context says is acting.
 *
 * An import only creates: an address already in the pool is refused, and the account there, its
 * password and its verified address included, is never touched. Only a pool that exists takes them.
 */
final readonly class ImportUser implements UserImport
{
    public function __construct(
        private ImportLine $lines,
        private UserRepository $users,
        private ConnectionRepository $connections,
        private TransactionManager $transactions,
        private RandomSource $random,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    #[\Override]
    public function import(#[\SensitiveParameter] string $line, ConnectionName $pool): User|ImportRefusal
    {
        if (! ($this->connections->find($pool)?->isDatabase() ?? false)) {
            // Only a pool takes accounts this way; one switched off or deleted since takes none.
            return new ImportRefusal('invalid_connection', 'Accounts are imported into a pool, and this is not one.');
        }
        $account = $this->lines->read($line);
        if ($account instanceof ImportRefusal) {
            return $account;
        }

        try {
            /** @var User */
            return $this->transactions->transactional(function () use ($account, $pool): User {
                $now = $this->clock->now();
                if ($this->users->findByEmail($pool, $account->email) !== null) {
                    throw new AlreadyExists('An account in this pool has that address.');
                }
                $user = User::register(
                    UserId::generate($this->random),
                    $account->email,
                    $account->passwordHash,
                    $now,
                    $pool,
                );
                $user->changeProfile(ProfileFields::apply(Profile::empty(), $account->profile), $now);
                $user->recordEmailVerification($account->emailVerified, $now);
                if (! $account->isActive) {
                    $user->deactivate($now);
                }
                $this->users->save($user);
                $this->events->dispatch(new UserCreated($user));

                return $user;
            });
        } catch (AlreadyExists) {
            return new ImportRefusal('already_exists', 'An account in this pool has that address.');
        } catch (InvalidValue $refusal) {
            // The domain's rules state the rule, never the value.
            $detail = $refusal->getMessage();

            return new ImportRefusal('invalid_field', $detail !== '' ? $detail : 'A field is not acceptable.');
        }
    }
}
