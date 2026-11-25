<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use DateTimeImmutable;

/**
 * The lifecycle of service provider keys this server makes itself (the `postgres` backend): a KMS
 * backend has none, its keys made at the provider. Nothing here returns key material: the store makes
 * a pair, seals its private halves, and never reads them back.
 */
interface ServiceProviderKeyStore
{
    /**
     * Make a signing and an encryption key with `$status`, each with its certificate (the encryption
     * key's signed by the signing key), and store them sealed.
     *
     * @return array{signing: ServiceProviderKey, encryption: ServiceProviderKey}
     *
     * @throws EncryptionUnavailable When a private half cannot be sealed: then nothing is stored.
     */
    public function createPair(ServiceProviderKeyStatus $status, DateTimeImmutable $now): array;

    /** Every key, locked until the transaction ends, so two rotations cannot both act. */
    public function lockAll(): ServiceProviderKeySet;

    /** Record a status change of a key this store returned. */
    public function save(ServiceProviderKey $key): void;

    /** @param non-empty-string $kid */
    public function delete(string $kid): void;

    public function all(): ServiceProviderKeySet;
}
