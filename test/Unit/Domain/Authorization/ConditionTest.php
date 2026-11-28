<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authorization;

use Clavia\Domain\Authorization\Condition;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A relationship's condition (docs/design/fine-grained-authorization.md §5.3): named as OpenFGA names
 * one, its context bounded, and no part of what the relationship is.
 */
final class ConditionTest extends TestCase
{
    public function testANameAndItsContextAreKept(): void
    {
        $condition = Condition::of('in_office', ['office' => '10.0.0.1']);

        self::assertSame('in_office', $condition->name);
        self::assertSame(['office' => '10.0.0.1'], $condition->context);
        self::assertSame([], Condition::of('weekday')->context);
    }

    /** @return iterable<string, array{string}> */
    public static function namesOpenFgaRefuses(): iterable
    {
        yield 'empty' => [''];
        yield 'a colon' => ['in:office'];
        yield 'a hash' => ['in#office'];
        yield 'an at' => ['in@office'];
        yield 'a space' => ['in office'];
        yield 'a trailing newline' => ["in_office\n"];
        yield 'too long' => [str_repeat('c', 51)];
    }

    #[DataProvider('namesOpenFgaRefuses')]
    public function testANameOpenFgaRefusesIsRefused(string $name): void
    {
        $this->expectException(InvalidValue::class);

        Condition::of($name);
    }

    public function testAContextOfMoreThanFourKibibytesIsRefused(): void
    {
        Condition::of('large', ['value' => str_repeat('x', Condition::MAX_CONTEXT_BYTES - 20)]);

        $this->expectException(InvalidValue::class);
        Condition::of('large', ['value' => str_repeat('x', Condition::MAX_CONTEXT_BYTES)]);
    }

    public function testARelationshipIsTheSameWhateverItsCondition(): void
    {
        $plain = Tuple::of(
            ObjectRef::fromString('folder:reports'),
            Relation::fromString('viewer'),
            SubjectRef::fromString('user:ada'),
        );
        $conditional = Tuple::of($plain->object, $plain->relation, $plain->subject, Condition::of('in_office'));

        self::assertTrue($plain->equals($conditional));
        self::assertSame('folder:reports#viewer@user:ada', $conditional->toString());
    }
}
