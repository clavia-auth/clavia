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
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Client\ClientLogoRepository;

/** `GET /api/v1/clients/{client_id}/logo`: the image the application's sign-in pages show. */
final readonly class ReadClientLogo
{
    public function __construct(private ClientLogoRepository $logos)
    {
    }

    /** @throws NotFound When the application has no logo, or does not exist. */
    public function __invoke(ClientId $id): ClientLogo
    {
        return $this->logos->find($id) ?? throw NotFound::of('logo');
    }
}
