<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Evaluation;

use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\InvalidValue;
use stdClass;

/**
 * Clavia as an information point (docs/design/fine-grained-authorization.md §2, "Context and
 * conditions"): what it knows of a question's subject, added to the context OpenFGA's conditions read
 * as `clavia.subject`, beyond the API's reach to forge. A model's condition reads it through a parameter
 * `clavia` of type `map<any>`.
 *
 * - A person: `id`, `connection`, `app_metadata` (always an object), `roles` (the names of their roles
 *   holding a permission on this API: an API learns nothing of another's), `mfa_enrolled` (an
 *   authenticator app confirmed, or a passkey).
 * - An application: `id`, `type` (`confidential` or `public`), `first_party`.
 *
 * Null means the subject is not one to ask about: a person with no account or a deactivated one, an
 * application that does not exist. The facts go to the engine only, never back to the caller.
 */
final readonly class SubjectFacts
{
    public function __construct(
        private UserRepository $users,
        private ClientRepository $clients,
        private RoleRepository $roles,
        private MfaFactorRepository $factors,
        private PasskeyRepository $passkeys,
    ) {
    }

    /** @return array<string, mixed>|null */
    public function of(ResourceServer $api, string $type, string $id): ?array
    {
        return match ($type) {
            'user' => $this->person($api, $id),
            'client' => $this->application($id),
            default => null,
        };
    }

    /** @return array<string, mixed>|null */
    private function person(ResourceServer $api, string $id): ?array
    {
        try {
            $user = $this->users->find(UserId::fromString($id));
        } catch (InvalidValue) {
            return null;
        }
        if ($user === null || ! $user->isActive()) {
            return null;
        }
        /** @var stdClass $metadata An object, even empty: a condition reads its members. */
        $metadata = json_decode($user->appMetadata()->toJson(), false, 16, JSON_THROW_ON_ERROR);

        return [
            'id' => $user->id->value,
            'connection' => $user->connection->value,
            'app_metadata' => $metadata,
            'roles' => array_values(array_map(
                static fn (Role $role): string => $role->name,
                array_filter(
                    $this->roles->rolesOf($user->id),
                    static fn (Role $role): bool => ! $role->grantsOn($api->id)->isEmpty(),
                ),
            )),
            'mfa_enrolled' => ($this->factors->find($user->id)?->isConfirmed() ?? false)
                || $this->passkeys->countOf($user->id) > 0,
        ];
    }

    /** @return array<string, mixed>|null */
    private function application(string $id): ?array
    {
        try {
            $client = $this->clients->find(ClientId::fromString($id));
        } catch (InvalidValue) {
            return null;
        }

        return $client === null ? null : [
            'id' => $client->id->value,
            'type' => $client->type->value,
            'first_party' => $client->isFirstParty(),
        ];
    }
}
