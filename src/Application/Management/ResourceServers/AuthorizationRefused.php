<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use DomainException;

/**
 * What `PUT /api/v1/resource-servers/{id}/authorization` was sent cannot be used: the decision
 * engine refused the model, or a client named cannot speak for an API. It points at the member at
 * fault (`/model`, `/clients/1`), and never repeats a value.
 */
final class AuthorizationRefused extends DomainException
{
    private function __construct(string $message, public readonly string $pointer)
    {
        parent::__construct($message);
    }

    /** The engine refused the model, with its own error code and nothing else it said. */
    public static function model(string $code): self
    {
        return new self(sprintf('The decision engine refused the model (%s).', $code), '/model');
    }

    public static function unknownClient(int $index): self
    {
        return new self('No such client.', '/clients/' . $index);
    }

    /**
     * A client that cannot ask for decisions: only a first-party machine client
     * (`client_credentials`) gets a token for the Authorization API.
     */
    public static function ineligibleClient(int $index): self
    {
        return new self(
            'A client speaking for an API is a first-party client holding the client_credentials grant.',
            '/clients/' . $index,
        );
    }
}
