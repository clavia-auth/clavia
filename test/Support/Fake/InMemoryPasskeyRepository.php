<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;

/**
 * Passkeys kept in an array, as copies: a passkey changed after it was fetched changes
 * nothing until it is saved, or its use is recorded.
 *
 * What the table's unique constraint decides, a scan of the credential ids decides here.
 */
final class InMemoryPasskeyRepository implements PasskeyRepository
{
    /** @var array<string, Passkey> By id. */
    private array $passkeys = [];

    #[\Override]
    public function save(Passkey $passkey): void
    {
        foreach ($this->passkeys as $other) {
            if ($other->credentialId->equals($passkey->credentialId) && ! $other->id->equals($passkey->id)) {
                throw new AlreadyExists('This credential is already registered.');
            }
        }

        // An existing passkey keeps its counter and backup state: only recordUse() moves them.
        $stored = $this->passkeys[$passkey->id->value] ?? null;
        if ($stored === null) {
            $this->passkeys[$passkey->id->value] = clone $passkey;

            return;
        }
        $stored->rename($passkey->name);
    }

    #[\Override]
    public function recordUse(Passkey $passkey, int $previousSignCount): bool
    {
        $stored = $this->passkeys[$passkey->id->value] ?? null;
        if ($stored === null || $stored->signCount !== $previousSignCount) {
            return false;
        }
        $this->passkeys[$passkey->id->value] = clone $passkey;

        return true;
    }

    #[\Override]
    public function ofCredentialId(CredentialId $credentialId): ?Passkey
    {
        foreach ($this->passkeys as $passkey) {
            if ($passkey->credentialId->equals($credentialId)) {
                return clone $passkey;
            }
        }

        return null;
    }

    #[\Override]
    public function ofUser(UserId $userId): array
    {
        $passkeys = array_values(array_filter(
            $this->passkeys,
            static fn (Passkey $passkey): bool => $passkey->userId->equals($userId),
        ));
        usort(
            $passkeys,
            static fn (Passkey $a, Passkey $b): int
                => [$a->createdAt, $a->id->value] <=> [$b->createdAt, $b->id->value],
        );

        return array_map(static fn (Passkey $passkey): Passkey => clone $passkey, $passkeys);
    }

    #[\Override]
    public function one(PasskeyId $id): ?Passkey
    {
        return isset($this->passkeys[$id->value]) ? clone $this->passkeys[$id->value] : null;
    }

    #[\Override]
    public function delete(PasskeyId $id): void
    {
        unset($this->passkeys[$id->value]);
    }

    #[\Override]
    public function countOf(UserId $userId): int
    {
        return count($this->ofUser($userId));
    }
}
