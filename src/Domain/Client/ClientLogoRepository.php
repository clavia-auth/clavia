<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

/**
 * Applications' logos ({@see ClientLogo}), at most one each, gone with the application.
 */
interface ClientLogoRepository
{
    /** Put this logo in place of the application's, if it had one. */
    public function save(ClientLogo $logo): void;

    public function find(ClientId $clientId): ?ClientLogo;

    /**
     * What a page names the logo by, without reading the image.
     *
     * @return non-empty-string|null Null when the application has none.
     */
    public function versionOf(ClientId $clientId): ?string;

    /**
     * The versions of these applications' logos, by client id; an application with none is left out.
     *
     * @param list<ClientId> $clientIds
     *
     * @return array<string, non-empty-string>
     */
    public function versionsOf(array $clientIds): array;

    /** @return bool Whether there was one. */
    public function delete(ClientId $clientId): bool;
}
