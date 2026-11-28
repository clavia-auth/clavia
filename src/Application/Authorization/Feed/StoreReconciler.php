<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Feed;

use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\FeedSubject;
use Clavia\Domain\Authorization\FeedSubjectKind;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\ReservedType;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;
use Clavia\Domain\Rbac\Role;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\Rbac\RoleRepository;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\PageRequest;

/**
 * Brings one subject into step in one API's store (docs/design/fine-grained-authorization.md §5.4),
 * from Clavia as it is now: what the store holds of it is read, what Clavia says it should hold is
 * worked out, and only the difference is written. Run twice, the second run writes nothing.
 *
 * What Clavia writes is role membership alone, `role:<id>#member@user:<id>`, and only in the stores
 * of the APIs the role holds a permission on. A person or an application that no longer exists loses
 * every relationship naming them in the store, those the API wrote included, so a reused id could
 * never inherit them.
 */
final readonly class StoreReconciler
{
    private const string MEMBER = 'member';

    /** Holders read at once from a role: the largest page. */
    private const int HOLDERS_PER_PAGE = PageRequest::MAX_PER_PAGE;

    public function __construct(
        private DecisionEngine $engine,
        private RoleRepository $roles,
        private UserRepository $users,
        private ClientRepository $clients,
    ) {
    }

    /**
     * @throws DecisionEngineFailed When the engine gives no answer, or refuses a write.
     */
    public function reconcile(ResourceServer $api, FeedSubject $subject): Reconciled
    {
        // An API whose authorization was taken away, store and all: nothing left to keep in step.
        $settings = $api->authorization;
        if ($settings === null) {
            return Reconciled::nothing();
        }

        return match ($subject->kind) {
            FeedSubjectKind::User => $this->user($api, $settings, UserId::fromString($subject->id)),
            FeedSubjectKind::Role => $this->role($api, $settings, RoleId::fromString($subject->id)),
            FeedSubjectKind::Client => $this->client($settings, $subject->id),
            FeedSubjectKind::EveryRole => $this->everyRole($api, $settings),
        };
    }

    /** The roles the person holds there; every relationship naming them once the account is gone. */
    private function user(ResourceServer $api, AuthorizationSettings $settings, UserId $id): Reconciled
    {
        $person = self::object(ReservedType::User, $id->value);
        if ($this->users->find($id) === null) {
            return $this->forget($settings, SubjectRef::object($person));
        }
        if (! self::takesRoles($settings)) {
            return Reconciled::nothing();
        }

        $held = $this->engine->readBySubject(
            $settings->store,
            SubjectRef::object($person),
            ObjectType::fromString(ReservedType::Role->value),
        );
        $wanted = array_map(
            static fn (Role $role): Tuple => self::membership($role->id, $id->value),
            array_values(array_filter(
                $this->roles->rolesOf($id),
                static fn (Role $role): bool => self::reaches($role, $api),
            )),
        );

        return $this->apply($settings, $held, $wanted);
    }

    /** The role's members there: none once it is deleted, or holds no permission on the API. */
    private function role(ResourceServer $api, AuthorizationSettings $settings, RoleId $id): Reconciled
    {
        if (! self::takesRoles($settings)) {
            return Reconciled::nothing();
        }
        $role = $this->roles->find($id);

        return $this->apply(
            $settings,
            $this->engine->readByObject($settings->store, self::object(ReservedType::Role, $id->value)),
            $role !== null && self::reaches($role, $api) ? $this->members($role) : [],
        );
    }

    /** Every relationship naming the application, once it is deleted. */
    private function client(AuthorizationSettings $settings, string $id): Reconciled
    {
        try {
            $client = ClientId::fromString($id);
            $application = self::object(ReservedType::Client, $client->value);
        } catch (InvalidValue) {
            // An id OpenFGA's notation cannot carry was never written there.
            return Reconciled::nothing();
        }
        if ($this->clients->find($client) !== null) {
            return Reconciled::nothing();
        }

        return $this->forget($settings, SubjectRef::object($application));
    }

    /**
     * Every role Clavia knows, one by one: what enabling an API, a new model, or `fga:resync` asks
     * for. A role deleted while the feed could not say so is not among them; its own entry, which is
     * never given up, removes its members.
     */
    private function everyRole(ResourceServer $api, AuthorizationSettings $settings): Reconciled
    {
        $done = Reconciled::nothing();
        foreach ($this->roles->all() as $role) {
            $done = $done->and($this->role($api, $settings, $role->id));
        }

        return $done;
    }

    /** Every relationship the subject is named in, on every type of the model that takes relations. */
    private function forget(AuthorizationSettings $settings, SubjectRef $subject): Reconciled
    {
        $held = [];
        foreach ($settings->model->types as $type) {
            if (ReservedType::of($type)?->isSubjectOnly() === true) {
                continue;
            }
            array_push($held, ...$this->engine->readBySubject($settings->store, $subject, $type));
        }

        return $this->apply($settings, $held, []);
    }

    /**
     * Write what is wanted and not held, delete what is held and not wanted, a hundred at a time.
     *
     * @param list<Tuple> $held
     * @param list<Tuple> $wanted
     */
    private function apply(AuthorizationSettings $settings, array $held, array $wanted): Reconciled
    {
        $heldBy = self::byNotation($held);
        $wantedBy = self::byNotation($wanted);
        $writes = array_values(array_diff_key($wantedBy, $heldBy));
        $deletes = array_values(array_diff_key($heldBy, $wantedBy));

        // Deletions first: a role taken away stops granting before anything is written.
        foreach (array_chunk($deletes, DecisionEngine::MAX_WRITES) as $chunk) {
            $this->engine->write($settings->store, $settings->modelId, [], $chunk);
        }
        foreach (array_chunk($writes, DecisionEngine::MAX_WRITES) as $chunk) {
            $this->engine->write($settings->store, $settings->modelId, $chunk);
        }

        return new Reconciled(count($writes), count($deletes));
    }

    /**
     * @param list<Tuple> $tuples
     *
     * @return array<string, Tuple>
     */
    private static function byNotation(array $tuples): array
    {
        $keyed = [];
        foreach ($tuples as $tuple) {
            $keyed[$tuple->toString()] = $tuple;
        }

        return $keyed;
    }

    /** @return list<Tuple> A membership for each holder of the role. */
    private function members(Role $role): array
    {
        $members = [];
        $page = 1;
        do {
            $holders = $this->roles->holders($role->id, PageRequest::of($page++, self::HOLDERS_PER_PAGE));
            foreach ($holders->items as $user) {
                $members[] = self::membership($role->id, $user->value);
            }
        } while ($holders->items !== [] && count($members) < $holders->total);

        return $members;
    }

    /** Whether the role holds a permission on the API: only then do its members reach its store. */
    private static function reaches(Role $role, ResourceServer $api): bool
    {
        return ! $role->grantsOn($api->id)->isEmpty();
    }

    /** A model without `role` takes no membership: nothing is written there. */
    private static function takesRoles(AuthorizationSettings $settings): bool
    {
        return $settings->model->declares(ObjectType::fromString(ReservedType::Role->value));
    }

    private static function membership(RoleId $role, string $user): Tuple
    {
        return Tuple::of(
            self::object(ReservedType::Role, $role->value),
            Relation::fromString(self::MEMBER),
            SubjectRef::object(self::object(ReservedType::User, $user)),
        );
    }

    private static function object(ReservedType $type, string $id): ObjectRef
    {
        return ObjectRef::of(ObjectType::fromString($type->value), $id);
    }
}
