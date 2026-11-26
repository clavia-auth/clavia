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
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Client\ClientLogoRepository;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Event\ClientLogoChanged;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PUT /api/v1/clients/{client_id}/logo`: the application's logo on the sign-in pages, in place of this
 * server's. The image is held to {@see ClientLogo}'s rules by its content, whatever the request says.
 */
final readonly class SetClientLogo
{
    public function __construct(
        private ClientRepository $clients,
        private ClientLogoRepository $logos,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws InvalidValue When it is not a PNG, JPEG or WebP image within the bounds.
     */
    public function __invoke(ClientId $id, string $image): ClientLogo
    {
        $client = $this->clients->find($id) ?? throw NotFound::of('client');
        $logo = ClientLogo::fromBytes($client->id, $image);
        $this->logos->save($logo);
        $this->events->dispatch(new ClientLogoChanged($client->id));

        return $logo;
    }
}
