<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Relationships;

use Clavia\Application\Authorization\SpeaksForNoApi;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\ReservedType;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `POST /access/v1/relationships` (docs/design/fine-grained-authorization.md §5.3): an API writes and
 * deletes the relationships of its own resources, at most a hundred, all or none, into its own store.
 *
 * Each relationship's object is one of the API's own types: Clavia's (`user`, `client`, `role`,
 * `group`) are written by Clavia alone, so no API can grant through the back door what a role grants.
 * A person or an application named as a subject must exist in Clavia; a userset (`team:sales#member`,
 * `role:<id>#member`) is the model's to accept. Whether the model takes each relationship, and the
 * condition it names, is the engine's to say. Nothing of the relationships is kept or logged here.
 */
final readonly class WriteRelationships
{
    public function __construct(
        private SpokenForApi $apis,
        private DecisionEngine $engine,
        private UserRepository $users,
        private ClientRepository $clients,
    ) {
    }

    /**
     * @param list<Tuple> $writes
     * @param list<Tuple> $deletes
     *
     * @throws SpeaksForNoApi
     * @throws RelationshipRefused Pointing at the first relationship at fault; nothing was written.
     * @throws DecisionEngineFailed When the engine gives no answer: nothing was written.
     */
    public function __invoke(ClientId $caller, array $writes, array $deletes): void
    {
        [, $settings] = $this->apis->of($caller);
        if (count($writes) + count($deletes) > DecisionEngine::MAX_WRITES) {
            throw RelationshipRefused::tooMany(DecisionEngine::MAX_WRITES);
        }
        foreach ($writes as $index => $tuple) {
            self::assertTheApis($settings->model, $tuple, '/writes/' . $index);
            $this->assertKnown($tuple, '/writes/' . $index);
        }
        foreach ($deletes as $index => $tuple) {
            // A deleted person's relationships may still be taken away: no subject is looked up.
            self::assertTheApis($settings->model, $tuple, '/deletes/' . $index);
        }

        try {
            $this->engine->write($settings->store, $settings->modelId, $writes, $deletes);
        } catch (DecisionEngineFailed $failed) {
            throw $failed->refusal === null ? $failed : RelationshipRefused::byEngine($failed->refusal);
        }
    }

    /** @throws RelationshipRefused */
    private static function assertTheApis(AuthorizationModel $model, Tuple $tuple, string $at): void
    {
        if (ReservedType::of($tuple->object->type) !== null) {
            throw RelationshipRefused::reservedType($at . '/resource/type');
        }
        if (! $model->declares($tuple->object->type)) {
            throw RelationshipRefused::unknownType($at . '/resource/type');
        }
    }

    /** @throws RelationshipRefused */
    private function assertKnown(Tuple $tuple, string $at): void
    {
        $subject = $tuple->subject;
        if ($subject->isUserset()) {
            return;
        }
        $known = match (ReservedType::of($subject->object->type)) {
            ReservedType::User => $this->userExists($subject->object->id),
            ReservedType::Client => $this->clientExists($subject->object->id),
            default => true,
        };
        if (! $known) {
            throw RelationshipRefused::unknownSubject($at . '/subject/id');
        }
    }

    private function userExists(string $id): bool
    {
        try {
            return $this->users->find(UserId::fromString($id)) !== null;
        } catch (InvalidValue) {
            return false;
        }
    }

    private function clientExists(string $id): bool
    {
        try {
            return $this->clients->find(ClientId::fromString($id)) !== null;
        } catch (InvalidValue) {
            return false;
        }
    }
}
