<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Support;

use Clavia\Application\Port\DecisionEngine;
use Clavia\Domain\Authorization\AuthorizationModel;
use ClaviaTest\Support\Contract\DecisionEngineContract;
use ClaviaTest\Support\Fake\FakeDecisionEngine;
use LogicException;

final class FakeDecisionEngineTest extends DecisionEngineContract
{
    private ?FakeDecisionEngine $engine = null;

    #[\Override]
    protected function engine(): DecisionEngine
    {
        return $this->engine ??= new FakeDecisionEngine();
    }

    #[\Override]
    protected function unreachableEngine(): DecisionEngine
    {
        $engine = new FakeDecisionEngine();
        $engine->goDown();

        return $engine;
    }

    public function testAModelBeyondTheUnionSubsetIsTheTestsMistakeNeverAWrongAnswer(): void
    {
        $this->expectException(LogicException::class);

        $this->engine()->writeModel($this->store(), AuthorizationModel::fromJson(<<<'JSON'
            {"schema_version": "1.1", "type_definitions": [
              {"type": "user"},
              {"type": "document", "relations": {
                "owner": {"this": {}},
                "blocked": {"this": {}},
                "viewer": {"difference": {
                  "base": {"computedUserset": {"relation": "owner"}},
                  "subtract": {"computedUserset": {"relation": "blocked"}}
                }}
              }, "metadata": {"relations": {
                "owner": {"directly_related_user_types": [{"type": "user"}]},
                "blocked": {"directly_related_user_types": [{"type": "user"}]}
              }}}
            ]}
            JSON));
    }

    public function testItCountsTheQuestionsAsked(): void
    {
        [$store, $model] = $this->modelled();
        $engine = $this->engine();
        self::assertInstanceOf(FakeDecisionEngine::class, $engine);

        $this->check($store, $model, 'document:1', 'viewer', 'user:ada');
        $engine->batchCheck($store, $model, [self::question('document:1', 'viewer', 'user:ada')]);

        self::assertSame(2, $engine->questions);
    }
}
