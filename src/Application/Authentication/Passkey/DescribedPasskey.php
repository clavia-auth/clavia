<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\Passkey;
use DateTimeImmutable;

/**
 * A passkey as its owner sees it on the account page: never its credential id or key.
 */
final readonly class DescribedPasskey
{
    public function __construct(
        public string $id,
        public string $name,
        public bool $synced,
        public DateTimeImmutable $createdAt,
        public ?DateTimeImmutable $lastUsedAt,
    ) {
    }

    public static function of(Passkey $passkey): self
    {
        return new self(
            $passkey->id->value,
            $passkey->name->value,
            $passkey->isSynced(),
            $passkey->createdAt,
            $passkey->lastUsedAt,
        );
    }
}
