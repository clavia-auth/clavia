<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\AccessCheck;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Application\Port\ModelVersion;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\Condition;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * What every {@see DecisionEngine} must do: OpenFGA itself, and the double the use cases are
 * tested with (docs/design/fine-grained-authorization.md §8).
 *
 * One model throughout, in OpenFGA's JSON: people, teams of people, folders, and documents in
 * folders. A document's viewer is a viewer named on it, one of its editors (computed), or a viewer
 * of its folder (through a parent); its editor is an editor named on it, a member of a team named
 * so (a userset), or its owner. Each test makes its own stores, and deletes them.
 */
abstract class DecisionEngineContract extends TestCase
{
    public const string MODEL = <<<'JSON'
        {
          "schema_version": "1.1",
          "type_definitions": [
            {"type": "user"},
            {
              "type": "team",
              "relations": {"member": {"this": {}}},
              "metadata": {"relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}}
            },
            {
              "type": "folder",
              "relations": {"viewer": {"this": {}}},
              "metadata": {"relations": {"viewer": {"directly_related_user_types": [{"type": "user"}]}}}
            },
            {
              "type": "document",
              "relations": {
                "parent": {"this": {}},
                "owner": {"this": {}},
                "editor": {"union": {"child": [{"this": {}}, {"computedUserset": {"relation": "owner"}}]}},
                "viewer": {"union": {"child": [
                  {"this": {}},
                  {"computedUserset": {"relation": "editor"}},
                  {"tupleToUserset": {"tupleset": {"relation": "parent"}, "computedUserset": {"relation": "viewer"}}}
                ]}}
              },
              "metadata": {"relations": {
                "parent": {"directly_related_user_types": [{"type": "folder"}]},
                "owner": {"directly_related_user_types": [{"type": "user"}]},
                "editor": {"directly_related_user_types": [{"type": "user"}, {"type": "team", "relation": "member"}]},
                "viewer": {"directly_related_user_types": [{"type": "user"}]}
              }}
            }
          ]
        }
        JSON;

    /**
     * A folder viewed by anybody named on it, or, under `in_office`, by somebody whose address is the
     * office's: OpenFGA's conditional relationships.
     */
    public const string CONDITIONAL_MODEL = <<<'JSON'
        {
          "schema_version": "1.1",
          "type_definitions": [
            {"type": "user"},
            {
              "type": "folder",
              "relations": {"viewer": {"this": {}}},
              "metadata": {"relations": {"viewer": {"directly_related_user_types": [
                {"type": "user"}, {"type": "user", "condition": "in_office"}
              ]}}}
            }
          ],
          "conditions": {
            "in_office": {
              "name": "in_office",
              "expression": "address == office",
              "parameters": {
                "address": {"type_name": "TYPE_NAME_STRING"},
                "office": {"type_name": "TYPE_NAME_STRING"}
              }
            }
          }
        }
        JSON;

    /** @var list<StoreId> */
    private array $stores = [];

    abstract protected function engine(): DecisionEngine;

    /** An engine that cannot be reached. */
    abstract protected function unreachableEngine(): DecisionEngine;

    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->stores as $store) {
            try {
                $this->engine()->deleteStore($store);
            } catch (DecisionEngineFailed) {
                // Deleted by the test itself.
            }
        }
        $this->stores = [];
    }

    public function testAStoreTakesAModelAndEveryWriteIsANewVersion(): void
    {
        $store = $this->store();
        $first = $this->engine()->writeModel($store, self::model());
        $second = $this->engine()->writeModel($store, self::model());

        self::assertFalse($first->equals($second));
        self::assertFalse($this->store()->equals($store));
    }

    public function testTheModelVersionsAreReadNewestFirstAPageAtATime(): void
    {
        $store = $this->store();
        $written = [];
        foreach (range(1, 3) as $ignored) {
            $written[] = $this->engine()->writeModel($store, self::model())->value;
        }

        $first = $this->engine()->readModels($store, 2);
        self::assertCount(2, $first->models);
        self::assertNotSame('', $first->next);
        $second = $this->engine()->readModels($store, 2, $first->next);
        self::assertSame('', $second->next);

        $read = array_map(
            static fn (ModelVersion $version): string => $version->id->value,
            [...$first->models, ...$second->models],
        );
        self::assertSame(array_reverse($written), $read);
        /** @var mixed $model */
        $model = json_decode($first->models[0]->json, false, 128, JSON_THROW_ON_ERROR);
        self::assertInstanceOf(stdClass::class, $model);
        self::assertSame('1.1', $model->schema_version ?? null);
        // `this` is an empty object, never a list.
        self::assertStringContainsString('"this":{}', str_replace(' ', '', $first->models[0]->json));
    }

    public function testAStoreWithoutAModelHasNoVersions(): void
    {
        $page = $this->engine()->readModels($this->store(), 10);

        self::assertSame([], $page->models);
        self::assertSame('', $page->next);
    }

    public function testARelationNamedOnTheObjectIsHeld(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#viewer@user:ada');

        self::assertTrue($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
        self::assertFalse($this->check($store, $model, 'document:1', 'viewer', 'user:bob'));
        self::assertFalse($this->check($store, $model, 'document:2', 'viewer', 'user:ada'));
        self::assertFalse($this->check($store, $model, 'document:1', 'editor', 'user:ada'));
    }

    public function testARelationIsHeldThroughAnotherOfTheSameObject(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#owner@user:ada');

        // The owner is an editor, and an editor a viewer.
        self::assertTrue($this->check($store, $model, 'document:1', 'editor', 'user:ada'));
        self::assertTrue($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
    }

    public function testARelationIsHeldThroughARelatedObject(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#parent@folder:reports', 'folder:reports#viewer@user:ada');

        self::assertTrue($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
        self::assertFalse($this->check($store, $model, 'document:1', 'editor', 'user:ada'));
        self::assertFalse($this->check($store, $model, 'document:2', 'viewer', 'user:ada'));
    }

    public function testARelationIsHeldThroughAUserset(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#editor@team:sales#member', 'team:sales#member@user:ada');

        self::assertTrue($this->check($store, $model, 'document:1', 'editor', 'user:ada'));
        self::assertTrue($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
        self::assertFalse($this->check($store, $model, 'document:1', 'editor', 'user:bob'));
        // The userset itself is a subject of the question.
        self::assertTrue($this->check($store, $model, 'document:1', 'editor', 'team:sales#member'));
    }

    public function testARelationshipDeletedIsNoLongerHeld(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#viewer@user:ada');

        $this->engine()->write($store, $model, [], [self::tuple('document:1#viewer@user:ada')]);

        // Strongly consistent: the very next question sees it.
        self::assertFalse($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
    }

    public function testAWriteIsAllOrNothing(): void
    {
        [$store, $model] = $this->modelled();

        try {
            // The second tuple is not one the model takes: a folder has no owner.
            $this->write($store, $model, 'document:1#viewer@user:ada', 'folder:reports#owner@user:ada');
            self::fail('The write was accepted.');
        } catch (DecisionEngineFailed $refused) {
            self::assertNotNull($refused->refusal);
        }

        self::assertFalse($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
    }

    /** @return iterable<string, array{string}> */
    public static function tuplesTheModelRefuses(): iterable
    {
        yield 'an undeclared type' => ['invoice:1#viewer@user:ada'];
        yield 'a relation the type lacks' => ['folder:reports#owner@user:ada'];
        yield 'a subject the relation does not take' => ['document:1#owner@team:sales'];
        yield 'a userset the relation does not take' => ['document:1#viewer@team:sales#member'];
    }

    #[DataProvider('tuplesTheModelRefuses')]
    public function testATupleTheModelDoesNotTakeIsRefused(string $tuple): void
    {
        [$store, $model] = $this->modelled();

        $this->expectException(DecisionEngineFailed::class);

        $this->write($store, $model, $tuple);
    }

    public function testATupleIsWrittenOnceAndDeletedOnlyWhenWritten(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#viewer@user:ada');

        $twice = [[self::tuple('document:1#viewer@user:ada')], []];
        $unwritten = [[], [self::tuple('document:2#viewer@user:ada')]];
        foreach ([$twice, $unwritten] as [$writes, $deletes]) {
            try {
                $this->engine()->write($store, $model, $writes, $deletes);
                self::fail('The write was accepted.');
            } catch (DecisionEngineFailed $refused) {
                self::assertNotNull($refused->refusal);
            }
        }
    }

    public function testAtMostAHundredTuplesAreWrittenAtOnce(): void
    {
        [$store, $model] = $this->modelled();
        $tuples = array_map(static fn (int $i): Tuple => self::tuple("document:$i#viewer@user:ada"), range(1, 60));

        $this->engine()->write($store, $model, array_slice($tuples, 0, 50), []);
        $this->engine()->write($store, $model, array_slice($tuples, 50), array_slice($tuples, 0, 40));
        self::assertTrue($this->check($store, $model, 'document:60', 'viewer', 'user:ada'));
        self::assertFalse($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));

        $this->expectException(InvalidArgumentException::class);
        $this->engine()->write($store, $model, $tuples, array_slice($tuples, 0, 41));
    }

    public function testNothingWrittenIsNothingAsked(): void
    {
        [$store, $model] = $this->modelled();

        $this->engine()->write($store, $model, [], []);

        self::assertFalse($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
    }

    public function testABatchIsAnsweredInTheOrderAskedWhateverItsSize(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#parent@folder:reports', 'folder:reports#viewer@user:ada');
        $this->write($store, $model, 'document:2#owner@user:bob');

        $checks = [];
        $expected = [];
        // More than OpenFGA takes in one batch check (50).
        foreach (range(1, 30) as $_) {
            $checks[] = self::question('document:1', 'viewer', 'user:ada');
            $checks[] = self::question('document:2', 'viewer', 'user:ada');
            $checks[] = self::question('document:2', 'editor', 'user:bob');
            array_push($expected, true, false, true);
        }

        self::assertSame($expected, $this->engine()->batchCheck($store, $model, $checks));
        self::assertSame([], $this->engine()->batchCheck($store, $model, []));
    }

    public function testTheObjectsASubjectHoldsARelationOnAreListed(): void
    {
        [$store, $model] = $this->modelled();
        $this->write(
            $store,
            $model,
            'document:1#parent@folder:reports',
            'folder:reports#viewer@user:ada',
            'document:2#owner@user:ada',
            'document:3#viewer@user:bob',
        );

        $objects = $this->engine()->listObjects(
            $store,
            $model,
            ObjectType::fromString('document'),
            Relation::fromString('viewer'),
            SubjectRef::fromString('user:ada'),
        );

        self::assertSame(['document:1', 'document:2'], self::sorted($objects));
    }

    public function testTheSubjectsHoldingARelationOnAnObjectAreListed(): void
    {
        [$store, $model] = $this->modelled();
        $this->write(
            $store,
            $model,
            'document:1#parent@folder:reports',
            'folder:reports#viewer@user:ada',
            'document:1#editor@team:sales#member',
            'team:sales#member@user:bob',
            'document:1#owner@user:cy',
            'document:2#viewer@user:dee',
        );

        $users = $this->engine()->listUsers(
            $store,
            $model,
            ObjectRef::fromString('document:1'),
            Relation::fromString('viewer'),
            ObjectType::fromString('user'),
        );

        self::assertSame(['user:ada', 'user:bob', 'user:cy'], self::sorted($users));
    }

    public function testTheRelationshipsWrittenWithASubjectAreReadBack(): void
    {
        [$store, $model] = $this->modelled();
        $tuples = array_map(static fn (int $i): string => "document:$i#viewer@user:ada", range(1, 70));
        // More than OpenFGA returns in one page (100).
        $this->write($store, $model, ...array_slice($tuples, 0, 50));
        $this->write($store, $model, ...array_slice($tuples, 50));
        $owned = array_map(static fn (int $i): string => "document:$i#owner@user:ada", range(1, 50));
        $this->write($store, $model, ...$owned);
        // Another subject, and the same subject on other types: not read.
        $this->write(
            $store,
            $model,
            'document:1#viewer@user:bob',
            'folder:reports#viewer@user:ada',
            'team:sales#member@user:ada',
        );
        $this->write($store, $model, 'document:1#editor@team:sales#member');

        $read = $this->engine()->readBySubject(
            $store,
            SubjectRef::fromString('user:ada'),
            ObjectType::fromString('document'),
        );

        $expected = [...$tuples, ...$owned];
        sort($expected);
        $found = array_map(static fn (Tuple $tuple): string => $tuple->toString(), $read);
        sort($found);
        self::assertSame($expected, $found);

        $usersets = $this->engine()->readBySubject(
            $store,
            SubjectRef::fromString('team:sales#member'),
            ObjectType::fromString('document'),
        );
        self::assertSame(['document:1#editor@team:sales#member'], array_map(
            static fn (Tuple $tuple): string => $tuple->toString(),
            $usersets,
        ));
    }

    public function testTheRelationshipsWrittenOnAnObjectAreReadBack(): void
    {
        [$store, $model] = $this->modelled();
        $members = array_map(static fn (int $i): string => "team:sales#member@user:u$i", range(1, 120));
        // More than OpenFGA returns in one page (100), over two writes.
        $this->write($store, $model, ...array_slice($members, 0, 100));
        $this->write($store, $model, ...array_slice($members, 100));
        // Another object of the same type, and the same object's id on another type: not read.
        $this->write($store, $model, 'team:support#member@user:u1', 'folder:sales#viewer@user:u1');
        $this->write($store, $model, 'document:1#editor@team:sales#member');

        $read = $this->engine()->readByObject($store, ObjectRef::fromString('team:sales'));

        $found = array_map(static fn (Tuple $tuple): string => $tuple->toString(), $read);
        sort($found);
        $expected = $members;
        sort($expected);
        self::assertSame($expected, $found);
        self::assertSame(
            ['document:1#editor@team:sales#member'],
            array_map(
                static fn (Tuple $tuple): string => $tuple->toString(),
                $this->engine()->readByObject($store, ObjectRef::fromString('document:1')),
            ),
        );
        self::assertSame([], $this->engine()->readByObject($store, ObjectRef::fromString('team:nobody')));
    }

    public function testARelationshipKeepsItsConditionAndContext(): void
    {
        $store = $this->store();
        $model = $this->engine()->writeModel($store, AuthorizationModel::fromJson(self::CONDITIONAL_MODEL));
        $conditional = Tuple::of(
            ObjectRef::fromString('folder:reports'),
            Relation::fromString('viewer'),
            SubjectRef::fromString('user:ada'),
            Condition::of('in_office', ['office' => '10.0.0.1']),
        );

        $this->engine()->write($store, $model, [$conditional, self::tuple('folder:reports#viewer@user:bob')]);

        $read = $this->engine()->readPage($store, ObjectRef::fromString('folder:reports'), 10)->tuples;
        usort($read, static fn (Tuple $a, Tuple $b): int => $a->toString() <=> $b->toString());
        self::assertSame(['folder:reports#viewer@user:ada', 'folder:reports#viewer@user:bob'], array_map(
            static fn (Tuple $tuple): string => $tuple->toString(),
            $read,
        ));
        $condition = $read[0]->condition;
        self::assertNotNull($condition);
        self::assertSame('in_office', $condition->name);
        self::assertSame(['office' => '10.0.0.1'], $condition->context);
        self::assertNull($read[1]->condition);
        // Deleted by what it is, whatever its condition.
        $this->engine()->write($store, $model, [], [self::tuple('folder:reports#viewer@user:ada')]);
        self::assertCount(1, $this->engine()->readPage($store, ObjectRef::fromString('folder:reports'), 10)->tuples);
    }

    public function testAConditionTheRelationDoesNotTakeIsRefused(): void
    {
        [$store, $model] = $this->modelled();

        try {
            $this->engine()->write($store, $model, [Tuple::of(
                ObjectRef::fromString('folder:reports'),
                Relation::fromString('viewer'),
                SubjectRef::fromString('user:ada'),
                Condition::of('in_office'),
            )]);
            self::fail('A condition the model does not declare was written.');
        } catch (DecisionEngineFailed $failed) {
            self::assertNotNull($failed->refusal);
        }
    }

    public function testAnObjectsRelationshipsAreReadAPageAtATime(): void
    {
        [$store, $model] = $this->modelled();
        $viewers = array_map(
            static fn (int $i): string => sprintf('folder:reports#viewer@user:u%03d', $i),
            range(1, 25),
        );
        $this->write($store, $model, ...$viewers);
        $this->write($store, $model, 'folder:archive#viewer@user:u001');

        $found = [];
        $token = '';
        $pages = 0;
        do {
            $page = $this->engine()->readPage($store, ObjectRef::fromString('folder:reports'), 10, $token);
            self::assertLessThanOrEqual(10, count($page->tuples));
            array_push($found, ...array_map(static fn (Tuple $tuple): string => $tuple->toString(), $page->tuples));
            $token = $page->next;
            ++$pages;
        } while ($token !== '' && $pages < 10);

        sort($found);
        self::assertSame($viewers, $found);
        self::assertGreaterThanOrEqual(3, $pages);
    }

    public function testAContinuationTokenThatIsNotTheEnginesIsRefused(): void
    {
        [$store] = $this->modelled();

        try {
            $this->engine()->readPage($store, ObjectRef::fromString('folder:reports'), 10, 'bm90LWEtdG9rZW4');
            self::fail('A forged continuation token was taken.');
        } catch (DecisionEngineFailed $failed) {
            self::assertNotNull($failed->refusal);
        }
    }

    public function testAStoreIsAWorldOfItsOwn(): void
    {
        [$store, $model] = $this->modelled();
        [$other, $otherModel] = $this->modelled();
        $this->write($store, $model, 'document:1#viewer@user:ada');

        self::assertFalse($this->check($other, $otherModel, 'document:1', 'viewer', 'user:ada'));
        self::assertSame([], $this->engine()->readBySubject(
            $other,
            SubjectRef::fromString('user:ada'),
            ObjectType::fromString('document'),
        ));
    }

    public function testANewModelVersionKeepsTheRelationships(): void
    {
        [$store, $model] = $this->modelled();
        $this->write($store, $model, 'document:1#owner@user:ada');

        $next = $this->engine()->writeModel($store, self::model());

        self::assertTrue($this->check($store, $next, 'document:1', 'viewer', 'user:ada'));
        self::assertTrue($this->check($store, $model, 'document:1', 'viewer', 'user:ada'));
    }

    /** @return iterable<string, array{string}> */
    public static function modelsThatDoNotHoldTogether(): iterable
    {
        yield 'a direct relation taking an undeclared type' => [<<<'JSON'
            {"schema_version": "1.1", "type_definitions": [
              {"type": "user"},
              {"type": "document", "relations": {"viewer": {"this": {}}},
               "metadata": {"relations": {"viewer": {"directly_related_user_types": [{"type": "group"}]}}}}
            ]}
            JSON];
        yield 'a relation computed from one the type lacks' => [<<<'JSON'
            {"schema_version": "1.1", "type_definitions": [
              {"type": "user"},
              {"type": "document", "relations": {"viewer": {"computedUserset": {"relation": "editor"}}}}
            ]}
            JSON];
        yield 'a parent relation the type lacks' => [<<<'JSON'
            {"schema_version": "1.1", "type_definitions": [
              {"type": "user"},
              {"type": "document", "relations": {
                "viewer": {"tupleToUserset": {
                  "tupleset": {"relation": "parent"},
                  "computedUserset": {"relation": "viewer"}
                }}
              }}
            ]}
            JSON];
    }

    #[DataProvider('modelsThatDoNotHoldTogether')]
    public function testAModelThatDoesNotHoldTogetherIsRefused(string $json): void
    {
        $store = $this->store();

        try {
            $this->engine()->writeModel($store, AuthorizationModel::fromJson($json));
            self::fail('The model was accepted.');
        } catch (DecisionEngineFailed $refused) {
            self::assertSame('invalid_authorization_model', $refused->refusal);
        }
    }

    public function testAnUnknownStoreOrAnotherStoresModelIsRefused(): void
    {
        [$store, $model] = $this->modelled();
        [, $otherModel] = $this->modelled();
        $unknown = StoreId::fromString('01JZZZZZZZZZZZZZZZZZZZZZZZ');

        foreach ([[$store, $otherModel], [$unknown, $model]] as [$askedStore, $askedModel]) {
            try {
                $this->check($askedStore, $askedModel, 'document:1', 'viewer', 'user:ada');
                self::fail('The question was answered.');
            } catch (DecisionEngineFailed $refused) {
                self::assertNotNull($refused->refusal);
            }
        }
    }

    public function testAQuestionAboutARelationTheTypeLacksIsRefused(): void
    {
        [$store, $model] = $this->modelled();

        $this->expectException(DecisionEngineFailed::class);

        $this->check($store, $model, 'folder:reports', 'owner', 'user:ada');
    }

    public function testABatchWithAQuestionTheEngineRefusesIsRefused(): void
    {
        [$store, $model] = $this->modelled();

        try {
            $this->engine()->batchCheck($store, $model, [
                self::question('folder:reports', 'viewer', 'user:ada'),
                self::question('folder:reports', 'owner', 'user:ada'),
            ]);
            self::fail('A batch with a question the model cannot answer was answered.');
        } catch (DecisionEngineFailed $failed) {
            self::assertNotNull($failed->refusal, 'Refused, as that question would be alone.');
        }
    }

    public function testAnEngineThatCannotBeReachedGivesNoAnswer(): void
    {
        $engine = $this->unreachableEngine();
        $store = StoreId::fromString('01JZZZZZZZZZZZZZZZZZZZZZZZ');
        $model = AuthorizationModelId::fromString('01JZZZZZZZZZZZZZZZZZZZZZZZ');
        $calls = [
            static fn (): mixed => $engine->createStore('reports-api'),
            static fn (): mixed => $engine->check($store, $model, self::question('document:1', 'viewer', 'user:ada')),
            static fn (): mixed => $engine->batchCheck(
                $store,
                $model,
                [self::question('document:1', 'viewer', 'user:ada')],
            ),
            static fn (): mixed => $engine->readBySubject(
                $store,
                SubjectRef::fromString('user:ada'),
                ObjectType::fromString('document'),
            ),
            static fn (): mixed => $engine->readByObject($store, ObjectRef::fromString('team:sales')),
            static fn (): mixed => $engine->readPage($store, ObjectRef::fromString('team:sales'), 10),
            static fn (): mixed => $engine->readModels($store, 10),
        ];

        foreach ($calls as $call) {
            try {
                $call();
                self::fail('An unreachable engine answered.');
            } catch (DecisionEngineFailed $failed) {
                self::assertNull($failed->refusal, 'Unavailable, not a refusal.');
            }
        }
    }

    protected function store(): StoreId
    {
        $store = $this->engine()->createStore('clavia-contract');
        $this->stores[] = $store;

        return $store;
    }

    /** @return array{StoreId, AuthorizationModelId} */
    protected function modelled(): array
    {
        $store = $this->store();

        return [$store, $this->engine()->writeModel($store, self::model())];
    }

    protected static function model(): AuthorizationModel
    {
        return AuthorizationModel::fromJson(self::MODEL);
    }

    protected function write(StoreId $store, AuthorizationModelId $model, string ...$tuples): void
    {
        $this->engine()->write($store, $model, array_values(array_map(self::tuple(...), $tuples)));
    }

    protected function check(
        StoreId $store,
        AuthorizationModelId $model,
        string $object,
        string $relation,
        string $subject,
    ): bool {
        return $this->engine()->check($store, $model, self::question($object, $relation, $subject));
    }

    protected static function question(string $object, string $relation, string $subject): AccessCheck
    {
        return AccessCheck::of(
            ObjectRef::fromString($object),
            Relation::fromString($relation),
            SubjectRef::fromString($subject),
        );
    }

    /** `object#relation@subject`, the subject possibly a userset (`team:sales#member`). */
    protected static function tuple(string $notation): Tuple
    {
        [$objectAndRelation, $subject] = array_pad(explode('@', $notation, 2), 2, '');
        [$object, $relation] = array_pad(explode('#', $objectAndRelation, 2), 2, '');

        return Tuple::of(
            ObjectRef::fromString($object),
            Relation::fromString($relation),
            SubjectRef::fromString($subject),
        );
    }

    /**
     * @param list<ObjectRef> $objects
     *
     * @return list<string>
     */
    private static function sorted(array $objects): array
    {
        $names = array_map(static fn (ObjectRef $object): string => $object->toString(), $objects);
        sort($names);

        return $names;
    }
}
