<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Oidc\SigningKey;
use DateTimeImmutable;

/**
 * The keys of a signing backend whose keys this server creates itself — `postgres` —
 * for managing their lifecycle: creation, rotation, listing.
 *
 * A KMS or HSM backend has no such store: there, creating a key is the provider's API
 * call and rotation is publishing a second key reference.
 *
 * Nothing here returns private key material, sealed or not. The store creates the key
 * pair and keeps the private half; only the backend's own {@see TokenSigner::sign()}
 * ever opens it.
 */
interface SigningKeyStore
{
    /**
     * Generate a key pair for `$algorithm`, store its private half sealed, and record it
     * as the active key.
     *
     * Must run inside a transaction that has retired the previous active key first:
     * at most one key is ever active.
     *
     * @throws EncryptionUnavailable When the private half cannot be sealed. It is then not stored at
     *                               all — there is no fallback to storing it in the clear.
     */
    public function create(SigningAlgorithm $algorithm, DateTimeImmutable $now): SigningKey;

    /**
     * The active key, locked until the surrounding transaction ends, so that two
     * rotations cannot both retire it. Refuses to run outside a transaction.
     */
    public function lockActive(): ?SigningKey;

    /** Record a status change of a key this store returned. */
    public function save(SigningKey $key): void;

    /**
     * Every key ever created, published or not: the active one first, then the others
     * newest first.
     *
     * @return list<SigningKey>
     */
    public function all(): array;
}
