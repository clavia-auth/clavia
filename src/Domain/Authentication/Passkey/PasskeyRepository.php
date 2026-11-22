<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;

/**
 * Passkeys. A passkey is removed with its account.
 */
interface PasskeyRepository
{
    /**
     * Store a passkey: a new one, or a changed name.
     *
     * Registering is the one way to make a passkey; what this writes of an existing one is its
     * name. The counter and the backup state change only through {@see self::recordUse()},
     * which is conditional.
     *
     * @throws AlreadyExists When another passkey holds the credential id: it belongs to one
     *                       account and one passkey.
     */
    public function save(Passkey $passkey): void;

    /**
     * Persist a use recorded on `$passkey` ({@see Passkey::recordUse()}): the counter, the
     * backup state and the time, but only if the stored counter is still `$previousSignCount`.
     *
     * Two sign-ins that raced with one counter cannot both pass: the loser finds the counter
     * moved and gets false, and is refused as a regression is, without the audit event.
     *
     * @return bool Whether this write won.
     */
    #[\NoDiscard]
    public function recordUse(Passkey $passkey, int $previousSignCount): bool;

    /** The passkey with that credential id, whoever owns it. */
    public function ofCredentialId(CredentialId $credentialId): ?Passkey;

    /**
     * The account's passkeys, oldest first.
     *
     * @return list<Passkey>
     */
    public function ofUser(UserId $userId): array;

    public function one(PasskeyId $id): ?Passkey;

    /** Remove it. Removing what is not there is removing nothing. */
    public function delete(PasskeyId $id): void;

    public function countOf(UserId $userId): int;
}
