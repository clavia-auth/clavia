<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\Management\JsonObject;
use Clavia\Adapter\Primary\Http\Management\Paging;
use Clavia\Adapter\Primary\Http\Management\UserFields;
use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Domain\Shared\InvalidValue;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * How handlers read what the middleware has already checked: bodies, profile changes,
 * paging parameters.
 */
final class RequestReadingTest extends TestCase
{
    public function testABodyIsReadWithTheTypesTheContractPromised(): void
    {
        $body = JsonObject::of([
            'name' => 'Ada',
            'is_active' => false,
            'redirect_uris' => ['https://a.test/cb'],
            'permissions' => [['value' => 'a']],
            'nickname' => null,
        ]);

        self::assertSame('Ada', $body->string('name'));
        self::assertFalse($body->bool('is_active'));
        self::assertSame(['https://a.test/cb'], $body->strings('redirect_uris'));
        self::assertSame('a', ($body->objects('permissions') ?? [])[0]->string('value'));
        self::assertNull($body->string('absent'));
        self::assertTrue($body->has('nickname'));
        self::assertFalse($body->has('absent'));
    }

    public function testAValueOfAnotherTypeIsADefectNotTheCallersMistake(): void
    {
        $this->expectException(LogicException::class);

        JsonObject::of(['name' => 5])->string('name');
    }

    public function testAProfileFieldSentAsNullIsAChangeAndAnAbsentOneIsNot(): void
    {
        $body = JsonObject::of(['name' => null, 'locale' => 'fr-FR', 'email' => 'x@y.test']);

        self::assertSame(['name' => null, 'locale' => 'fr-FR'], UserFields::profileChanges($body));
        self::assertSame(['locale' => 'fr-FR'], UserFields::profile($body));
    }

    public function testPagingTakesTheContractsDefaults(): void
    {
        $request = Paging::fromQuery(RequestParameters::fromMap([]));

        self::assertSame([1, 50, ''], [$request->page, $request->perPage, $request->search]);

        $request = Paging::fromQuery(RequestParameters::fromMap(['page' => '3', 'per_page' => '10', 'q' => 'ada']));

        self::assertSame([3, 10, 'ada'], [$request->page, $request->perPage, $request->search]);
    }

    public function testAPageNumberThatIsNotAnIntegerIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        Paging::fromQuery(RequestParameters::fromMap(['page' => '1.5']));
    }
}
