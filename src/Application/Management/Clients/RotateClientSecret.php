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
use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /api/v1/clients/{client_id}/rotate-secret`: the way back from a lost secret.
 *
 * It needs no knowledge of the old one — only a hash was kept, so there is nothing to
 * compare — and works on the client the caller authenticates as: tokens already issued
 * are untouched, and only the next token request needs the new secret.
 */
final readonly class RotateClientSecret
{
    public function __construct(
        private ClientRepository $clients,
        private PasswordHasher $hasher,
        private SecretGenerator $secrets,
    ) {
    }

    /**
     * @throws NotFound
     * @throws InvalidValue When the client is public: it has no secret.
     */
    public function __invoke(ClientId $id): ClientWithSecret
    {
        $client = $this->clients->find($id) ?? throw NotFound::of('client');

        $secret = $this->secrets->token();
        $rotated = $client->withSecretHash($this->hasher->hash($secret));
        $this->clients->save($rotated);

        return new ClientWithSecret($rotated, $secret);
    }
}
