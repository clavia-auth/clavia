<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientLogoRepository;
use Clavia\Domain\Client\Event\ClientLogoRemoved;

/**
 * `DELETE /api/v1/clients/{client_id}/logo`: the pages show this server's logo again.
 */
final readonly class RemoveClientLogo
{
    public function __construct(
        private ClientLogoRepository $logos,
        private DomainEvents $events,
    ) {
    }

    /** @throws NotFound When the application has no logo, or does not exist. */
    public function __invoke(ClientId $id): void
    {
        if (! $this->logos->delete($id)) {
            throw NotFound::of('logo');
        }
        $this->events->dispatch(new ClientLogoRemoved($id));
    }
}
