<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\Event\AuthorizationEnabled;
use Clavia\Domain\Authorization\Event\AuthorizationModelWritten;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\ResourceServer\Event\ResourceServerChanged;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\InvalidValue;
use stdClass;
use Throwable;

/**
 * `PUT /api/v1/resource-servers/{resource_server_id}/authorization`: fine-grained authorization on
 * an API, switched on with this model and these clients speaking for it
 * (docs/design/fine-grained-authorization.md §5.1).
 *
 * In order: the API (a system API is refused before anything else is asked), the clients (each a
 * first-party machine client), the API's store in the decision engine (created the first time, kept
 * ever after), the model (written as a new version only when it differs from the one in force: the
 * engine keeps every version, and the store's relationships with them), then the settings, saved and
 * announced in one transaction. A store created for a request that then fails is deleted again, so a
 * refusal leaves nothing behind it.
 *
 * The identity tuples a store needs (every holder of every role with a permission on the API) are the
 * identity feed's, a later slice.
 */
final readonly class ConfigureAuthorization
{
    /**
     * @param bool $available Whether fine-grained authorization is on (`CLAVIA_FGA_URL`).
     */
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private ClientRepository $clients,
        private DecisionEngine $engine,
        private TransactionManager $transactions,
        private DomainEvents $events,
        private bool $available,
    ) {
    }

    /**
     * @param list<ClientId> $clients
     *
     * @throws NotFound
     * @throws SystemApiProtected For a system API.
     * @throws Conflict When fine-grained authorization is off on this server.
     * @throws AuthorizationRefused When a client cannot speak for an API, or the engine refuses the model.
     * @throws InvalidValue When more than twenty clients are named, or one twice.
     * @throws AlreadyExists When a client already speaks for another API.
     * @throws DecisionEngineFailed When the engine gives no answer: nothing was changed.
     */
    public function __invoke(
        ResourceServerId $id,
        AuthorizationModel $model,
        array $clients,
        bool $denialReasons,
    ): ResourceServer {
        $api = $this->resourceServers->find($id) ?? throw NotFound::of('API');
        if ($api->isSystem) {
            throw SystemApiProtected::authorization($api);
        }
        if (! $this->available) {
            throw new Conflict('Fine-grained authorization is off on this server: it names no decision engine.');
        }
        $this->assertEligible($clients);

        $current = $api->authorization;
        $store = $current->store ?? $this->engine->createStore('clavia-' . $api->id->value);

        try {
            $modelId = $current !== null && self::sameModel($current->model, $model)
                ? $current->modelId
                : $this->writeModel($store, $model);
            $settings = AuthorizationSettings::of(true, $store, $modelId, $model, $clients, $denialReasons);
            $configured = $api->withAuthorization($settings);

            $this->transactions->transactional(function () use ($configured, $current, $settings): void {
                $this->resourceServers->save($configured);
                if ($current?->enabled !== true) {
                    $this->events->dispatch(new AuthorizationEnabled($configured->id, $settings->store));
                }
                if ($current === null || ! $current->modelId->equals($settings->modelId)) {
                    $this->events->dispatch(new AuthorizationModelWritten($configured->id, $settings->modelId));
                }
                $changed = self::changed($current, $settings);
                if ($changed !== []) {
                    $this->events->dispatch(new ResourceServerChanged($configured->id, $changed));
                }
            });
        } catch (Throwable $failure) {
            if ($current === null) {
                $this->forget($store);
            }

            throw $failure;
        }

        return $configured;
    }

    /**
     * @param list<ClientId> $clients
     *
     * @throws AuthorizationRefused
     */
    private function assertEligible(array $clients): void
    {
        foreach ($clients as $index => $id) {
            $client = $this->clients->find($id) ?? throw AuthorizationRefused::unknownClient($index);
            if (! $client->isFirstParty() || ! $client->mayUseGrant(GrantType::ClientCredentials)) {
                throw AuthorizationRefused::ineligibleClient($index);
            }
        }
    }

    /**
     * @throws AuthorizationRefused When the engine refuses the model.
     * @throws DecisionEngineFailed When it gives no answer.
     */
    private function writeModel(StoreId $store, AuthorizationModel $model): AuthorizationModelId
    {
        try {
            return $this->engine->writeModel($store, $model);
        } catch (DecisionEngineFailed $failed) {
            throw $failed->refusal === null ? $failed : AuthorizationRefused::model($failed->refusal);
        }
    }

    /**
     * A store created for a request that failed, deleted again. Best effort: its id is forgotten
     * either way, and only Clavia, which no longer knows it, could ever ask with it.
     */
    private function forget(StoreId $store): void
    {
        try {
            $this->engine->deleteStore($store);
        } catch (DecisionEngineFailed) {
            // Logged by the adapter; nothing more to do.
        }
    }

    /**
     * Whether two models say the same: the same JSON, whatever its spacing or the order of an
     * object's members. Objects stay objects (decoded as such), so `{}` and `[]` stay apart.
     */
    private static function sameModel(AuthorizationModel $current, AuthorizationModel $model): bool
    {
        return self::canonical(json_decode($current->json, false, 64, JSON_THROW_ON_ERROR))
            === self::canonical(json_decode($model->json, false, 64, JSON_THROW_ON_ERROR));
    }

    private static function canonical(mixed $value): string
    {
        if ($value instanceof stdClass) {
            $members = get_object_vars($value);
            ksort($members, SORT_STRING);

            return '{' . implode(',', array_map(
                static fn (string|int $name, mixed $member): string => json_encode((string) $name, JSON_THROW_ON_ERROR)
                    . ':' . self::canonical($member),
                array_keys($members),
                $members,
            )) . '}';
        }
        if (is_array($value)) {
            return '[' . implode(',', array_map(self::canonical(...), $value)) . ']';
        }

        return json_encode($value, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION);
    }

    /**
     * What changed of the settings beside the model, by name: the speaking clients, whether denials
     * carry a reason.
     *
     * @return list<string>
     */
    private static function changed(?AuthorizationSettings $current, AuthorizationSettings $settings): array
    {
        $ids = static fn (?AuthorizationSettings $of): array => array_map(
            static fn (ClientId $client): string => $client->value,
            $of->clients ?? [],
        );
        $changed = [];
        if ($ids($current) !== $ids($settings)) {
            $changed[] = 'authorization.clients';
        }
        if (($current->denialReasons ?? false) !== $settings->denialReasons) {
            $changed[] = 'authorization.denial_reasons';
        }

        return $changed;
    }
}
