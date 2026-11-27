<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Fine-grained authorization on one API (docs/design/fine-grained-authorization.md §4): its store in
 * the decision engine, the model in force there, and the clients that speak for it.
 *
 * Switched off, the store and its relationships are kept, so switching it on again brings them
 * back; only a deletion the operator confirms removes the store, and the settings with it.
 *
 * A client speaks for one API at most, which is how a question that names no API is answered from
 * the right model: the storage holds that rule, as it holds every uniqueness.
 */
final readonly class AuthorizationSettings
{
    /** The most clients that may speak for one API. */
    public const int MAX_CLIENTS = 20;

    /**
     * @param list<ClientId> $clients Distinct, in the order given.
     */
    private function __construct(
        public bool $enabled,
        public StoreId $store,
        public AuthorizationModelId $modelId,
        public AuthorizationModel $model,
        public array $clients,
        public bool $denialReasons,
    ) {
    }

    /**
     * @param list<ClientId> $clients The clients that speak for the API.
     * @param bool $denialReasons Whether a denial says which kind it is (`no_relation`,
     *                            `subject_inactive`, `unknown_type`), never more.
     *
     * @throws InvalidValue When a client is named twice, or more than twenty are.
     */
    public static function of(
        bool $enabled,
        StoreId $store,
        AuthorizationModelId $modelId,
        AuthorizationModel $model,
        array $clients,
        bool $denialReasons,
    ): self {
        if (count($clients) > self::MAX_CLIENTS) {
            throw new InvalidValue('At most twenty clients speak for one API.');
        }
        $names = array_map(static fn (ClientId $client): string => $client->value, $clients);
        if (count(array_unique($names)) !== count($names)) {
            throw new InvalidValue('A client is named once among those speaking for an API.');
        }

        return new self($enabled, $store, $modelId, $model, $clients, $denialReasons);
    }

    /** The same settings, switched off: the store and its relationships kept. */
    public function disabled(): self
    {
        return clone($this, ['enabled' => false]);
    }

    public function speaksFor(ClientId $client): bool
    {
        return array_any($this->clients, static fn (ClientId $speaking): bool => $speaking->equals($client));
    }
}
