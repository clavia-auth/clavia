<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * Brings the database schema to the version this build of the code expects.
 *
 * Migrations only go forward. Undoing a change is a new migration, written and
 * reviewed like any other — never a "down" script nobody has ever run.
 */
interface SchemaMigrator
{
    /**
     * Apply every migration that has not been applied yet, oldest first.
     *
     * Safe to run from several processes at once: one applies, the others wait and then
     * find nothing left to do.
     *
     * @return list<MigrationStatus> The migrations this call applied, in order. Empty when up to date.
     *
     * @throws SchemaMigrationFailed When a migration cannot be applied, or the recorded history and
     *                               the migrations on disk disagree.
     */
    public function migrate(): array;

    /**
     * Every known migration, applied or pending, oldest first.
     *
     * @return list<MigrationStatus>
     *
     * @throws SchemaMigrationFailed When the recorded history and the migrations on disk disagree.
     */
    public function status(): array;
}
