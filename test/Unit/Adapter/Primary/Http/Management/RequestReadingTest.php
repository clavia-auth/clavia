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
use Clavia\Adapter\Primary\Http\Management\UserFields;
use LogicException;
use PHPUnit\Framework\TestCase;
use stdClass;

/**
 * How handlers read what the middleware has already checked: bodies and profile changes.
 */
final class RequestReadingTest extends TestCase
{
    public function testABodyIsReadWithTheTypesTheContractPromised(): void
    {
        $body = self::body('{"name":"Ada","is_active":false,"redirect_uris":["https://a.test/cb"],'
            . '"permissions":[{"value":"a"}],"nickname":null}');

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

        self::body('{"name":5}')->string('name');
    }

    public function testAProfileFieldSentAsNullIsAChangeAndAnAbsentOneIsNot(): void
    {
        $body = self::body('{"name":null,"locale":"fr-FR","email":"x@y.test"}');

        self::assertSame(['name' => null, 'locale' => 'fr-FR'], UserFields::profileChanges($body));
        self::assertSame(['locale' => 'fr-FR'], UserFields::profile($body));
    }

    private static function body(string $json): JsonObject
    {
        $decoded = json_decode($json, false, flags: JSON_THROW_ON_ERROR);
        self::assertInstanceOf(stdClass::class, $decoded);

        return JsonObject::of($decoded);
    }
}
