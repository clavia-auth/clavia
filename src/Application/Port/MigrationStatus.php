<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use DateTimeImmutable;

/**
 * One schema migration and whether the database has it.
 */
final readonly class MigrationStatus
{
    /**
     * @param non-empty-string       $version   Sortable identifier taken from the file name: `0003`.
     * @param non-empty-string       $name      What it does, from the file name: `refresh_tokens`.
     * @param DateTimeImmutable|null $appliedAt When it was applied; null while pending.
     */
    public function __construct(
        public string $version,
        public string $name,
        public ?DateTimeImmutable $appliedAt,
    ) {
    }

    public function isApplied(): bool
    {
        return $this->appliedAt !== null;
    }
}
