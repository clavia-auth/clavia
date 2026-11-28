<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authorization;

use Clavia\Application\Authorization\Evaluation\SubjectFacts;
use Clavia\Application\Authorization\Search\SearchAccess;
use Clavia\Application\Authorization\Search\SearchRequest;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationSettings;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\Audience;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryClientRepository;
use ClaviaTest\Support\Fake\InMemoryMfaFactorRepository;
use ClaviaTest\Support\Fake\InMemoryPasskeyRepository;
use ClaviaTest\Support\Fake\InMemoryResourceServerRepository;
use ClaviaTest\Support\Fake\InMemoryRoleRepository;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use ClaviaTest\Support\Fake\InMemoryUserRepository;
use PHPUnit\Framework\TestCase;

/**
 * A search's cap and its pages (#140, AuthZEN 1.0 §8.2): never more than the cap, whatever the engine
 * finds, sorted by id, each page continuing where the last stopped.
 */
final class SearchAccessTest extends TestCase
{
    private const string MODEL = <<<'JSON'
        {"schema_version": "1.1", "type_definitions": [
          {"type": "user"},
          {"type": "document", "relations": {"viewer": {"this": {}}},
           "metadata": {"relations": {"viewer": {"directly_related_user_types": [{"type": "user"}]}}}}
        ]}
        JSON;

    private const string ADA = '6b1f4a52-3c1e-4d7a-9a0b-2f5e8c9d1a01';

    public function testASearchConsidersNoMoreThanItsCapAndPagesThroughThem(): void
    {
        $clock = new FrozenClock();
        $engine = new FakeDecisionEngine();
        $apis = new InMemoryResourceServerRepository();
        $users = new InMemoryUserRepository();
        $clients = new InMemoryClientRepository();
        $model = AuthorizationModel::fromJson(self::MODEL);
        $store = $engine->createStore('clavia-test');
        $modelId = $engine->writeModel($store, $model);
        $apis->save(ResourceServer::register(
            ResourceServerId::fromString('rs_AAAAAAAAAAAAAAAA'),
            Audience::fromString('https://documents.example/api/'),
            'Documents',
            [],
            $clock->now(),
        )->withAuthorization(
            AuthorizationSettings::of(true, $store, $modelId, $model, [ClientId::fromString('backend')], false),
        ));
        $users->save(User::register(UserId::fromString(self::ADA), 'ada@example.com', null, $clock->now()));
        // Five documents, written out of order.
        $engine->write($store, $modelId, array_map(
            static fn (string $id): Tuple => Tuple::of(
                ObjectRef::fromString('document:' . $id),
                Relation::fromString('viewer'),
                SubjectRef::fromString('user:' . self::ADA),
            ),
            ['e', 'b', 'd', 'a', 'c'],
        ));
        $search = new SearchAccess(
            new SpokenForApi($apis),
            $engine,
            new SubjectFacts(
                $users,
                $clients,
                new InMemoryRoleRepository($apis, $users),
                new InMemoryMfaFactorRepository(new InMemoryTransactionManager()),
                new InMemoryPasskeyRepository(),
            ),
            $users,
            $clients,
            maxResults: 3,
        );

        $found = [];
        $token = '';
        do {
            $page = $search->resources(
                ClientId::fromString('backend'),
                new SearchRequest('user', self::ADA, 'viewer', 'document', '', [], 2, $token),
            );
            $found[] = $page->ids;
            $token = $page->nextToken;
        } while ($token !== '');

        self::assertSame([['a', 'b'], ['c']], $found, 'The first three by id, two at a time.');
    }
}
