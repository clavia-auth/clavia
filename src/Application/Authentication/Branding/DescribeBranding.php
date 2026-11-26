<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Branding;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Client\ClientLogoRepository;
use Clavia\Domain\Client\ClientRepository;

/**
 * The look of an application's sign-in pages, and the two files behind it: its logo, and its colour.
 * Read only, and by the client id alone: a page names its application through the request it holds.
 */
final readonly class DescribeBranding
{
    public function __construct(
        private ClientRepository $clients,
        private ClientLogoRepository $logos,
    ) {
    }

    /** Null for an application that does not exist (any more). */
    public function __invoke(ClientId $clientId): ?Branding
    {
        $client = $this->clients->find($clientId);

        return $client === null ? null : new Branding(
            $client->id,
            $client->name,
            $client->accentColor,
            $this->logos->versionOf($client->id),
        );
    }

    public function logo(ClientId $clientId): ?ClientLogo
    {
        return $this->logos->find($clientId);
    }
}
