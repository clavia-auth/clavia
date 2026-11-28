<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * The registered APIs.
 */
interface ResourceServerRepository
{
    public function find(ResourceServerId $id): ?ResourceServer;

    /** The API whose identifier is exactly `$identifier` — the `audience` a client names. */
    public function findByIdentifier(Audience $identifier): ?ResourceServer;

    /**
     * Create the API, or replace its name and permissions. The identifier never changes.
     *
     * @throws AlreadyExists When another API is registered with the identifier.
     */
    public function save(ResourceServer $resourceServer): void;

    /**
     * Remove the API, and with it its permissions and every client grant on it.
     */
    public function delete(ResourceServerId $id): void;

    /**
     * APIs newest first, searching the identifier and the name.
     *
     * @return Page<ResourceServer>
     */
    public function page(PageRequest $request): Page;

    /**
     * Every API with fine-grained authorization set up, switched on or off: those with a store of
     * their own in the decision engine, oldest first.
     *
     * @return list<ResourceServer>
     */
    public function withAuthorization(): array;

    /**
     * The API the client speaks for in fine-grained authorization (docs/design/fine-grained-authorization.md
     * §2), switched on or off: at most one, since a client speaks for one API.
     */
    public function spokenForBy(ClientId $client): ?ResourceServer;
}
