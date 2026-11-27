<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authorization;

use Clavia\Domain\Authorization\AuthorizationModelId;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\StoreId;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Objects, subjects, relations and tuples, held to OpenFGA's rules for each, so nothing that
 * exists here is refused by the engine for its spelling, or read by it as something else.
 */
final class RelationshipNotationTest extends TestCase
{
    public function testAnObjectIsATypeAndAnId(): void
    {
        $object = ObjectRef::fromString('document:3f2b8c1e-0a4d-4c5e-9f1a-2b3c4d5e6f70');

        self::assertSame('document', $object->type->value);
        self::assertSame('3f2b8c1e-0a4d-4c5e-9f1a-2b3c4d5e6f70', $object->id);
        self::assertSame('document:3f2b8c1e-0a4d-4c5e-9f1a-2b3c4d5e6f70', $object->toString());
        self::assertTrue($object->equals(ObjectRef::of(ObjectType::fromString('document'), $object->id)));
        self::assertFalse($object->equals(ObjectRef::fromString('folder:' . $object->id)));
    }

    /** @return iterable<string, array{string}> */
    public static function notObjects(): iterable
    {
        yield 'no id' => ['document:'];
        yield 'no type' => [':42'];
        yield 'no colon' => ['document'];
        yield 'two colons' => ['document:4:2'];
        yield 'a wildcard' => ['user:*'];
        yield 'a userset' => ['team:sales#member'];
        yield 'a space' => ['document:4 2'];
        yield 'a newline' => ["document:42\n"];
        yield 'an @ in the type' => ['doc@ument:42'];
        yield 'past 256 characters' => ['document:' . str_repeat('a', 248)];
    }

    #[DataProvider('notObjects')]
    public function testAnObjectIsRefusedWhenOpenFgaWouldReadItOtherwise(string $value): void
    {
        $this->expectException(InvalidValue::class);

        ObjectRef::fromString($value);
    }

    public function testAnObjectMayBeTwoHundredAndFiftySixCharacters(): void
    {
        self::assertSame(256, strlen(ObjectRef::fromString('document:' . str_repeat('a', 247))->toString()));
    }

    public function testATypeIsAtMost254CharactersAndARelation50(): void
    {
        self::assertSame(254, strlen(ObjectType::fromString(str_repeat('t', 254))->value));
        self::assertSame(50, strlen(Relation::fromString(str_repeat('r', 50))->name));

        $refusals = [
            static fn (): mixed => ObjectType::fromString(str_repeat('t', 255)),
            static fn (): mixed => Relation::fromString(str_repeat('r', 51)),
            static fn (): mixed => Relation::fromString(''),
            static fn (): mixed => Relation::fromString('view#er'),
        ];
        foreach ($refusals as $refused) {
            try {
                $refused();
                self::fail('The name was accepted.');
            } catch (InvalidValue $refused) {
                self::assertNotSame('', $refused->getMessage());
            }
        }
    }

    public function testASubjectIsAnObjectOrAUserset(): void
    {
        $person = SubjectRef::fromString('user:ada');
        $team = SubjectRef::fromString('team:sales#member');

        self::assertFalse($person->isUserset());
        self::assertTrue($team->isUserset());
        self::assertSame('member', $team->relation?->name);
        self::assertSame('team:sales#member', $team->toString());
        self::assertTrue(
            $team->equals(SubjectRef::userset(ObjectRef::fromString('team:sales'), Relation::fromString('member'))),
        );
        self::assertFalse($person->equals(SubjectRef::fromString('user:ada#member')));

        $this->expectException(InvalidValue::class);
        SubjectRef::fromString('team:sales#member#owner');
    }

    public function testATupleIsWrittenInZanzibarsNotation(): void
    {
        $tuple = Tuple::of(
            ObjectRef::fromString('document:42'),
            Relation::fromString('editor'),
            SubjectRef::fromString('team:sales#member'),
        );

        self::assertSame('document:42#editor@team:sales#member', $tuple->toString());
        self::assertTrue($tuple->equals(Tuple::of(
            ObjectRef::fromString('document:42'),
            Relation::fromString('editor'),
            SubjectRef::fromString('team:sales#member'),
        )));
    }

    public function testTheEnginesIdentifiersAreUlids(): void
    {
        self::assertSame('01M8FK326S0X3Q8SV2DT1CJ0D8', StoreId::fromString('01M8FK326S0X3Q8SV2DT1CJ0D8')->value);
        self::assertTrue(
            AuthorizationModelId::fromString('01M8FKE528M06BXFZAA8B6THG3')
                ->equals(AuthorizationModelId::fromString('01M8FKE528M06BXFZAA8B6THG3')),
        );

        // Lower case, a letter Crockford's base 32 leaves out, a first character past 7, a length.
        $notUlids = [
            '01m8fk326s0x3q8sv2dt1cj0d8',
            '01M8FK326S0X3Q8SV2DT1CJ0DU',
            '81M8FK326S0X3Q8SV2DT1CJ0D8',
            '01M8FK326S0X3Q8SV2DT1CJ0D',
        ];
        foreach ($notUlids as $value) {
            try {
                StoreId::fromString($value);
                self::fail(sprintf('%s was accepted.', $value));
            } catch (InvalidValue $refused) {
                self::assertNotSame('', $refused->getMessage());
            }
        }
    }
}
