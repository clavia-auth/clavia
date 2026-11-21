<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\OAuth2;

use Clavia\Application\OAuth2\RequestParameters;
use PHPUnit\Framework\TestCase;

final class RequestParametersTest extends TestCase
{
    public function testAParameterIsReadByName(): void
    {
        $parameters = new RequestParameters(['scope' => ['openid profile']]);

        self::assertSame('openid profile', $parameters->get('scope'));
    }

    public function testAnAbsentAndAnEmptyParameterAreTheSameThing(): void
    {
        // RFC 6749 §3.1: "Parameters sent without a value MUST be treated as if they
        // were omitted from the request."
        $parameters = new RequestParameters(['state' => ['']]);

        self::assertNull($parameters->get('state'));
        self::assertNull($parameters->get('missing'));
    }

    public function testARepetitionIsVisible(): void
    {
        $parameters = new RequestParameters([
            'client_id' => ['spa'],
            'redirect_uri' => ['https://a.example/cb', 'https://b.example/cb'],
            'scope' => ['openid', 'openid'],
        ]);

        self::assertFalse($parameters->isRepeated('client_id'));
        self::assertTrue($parameters->isRepeated('redirect_uri'));
        self::assertFalse($parameters->isRepeated('missing'));
        self::assertSame(['redirect_uri', 'scope'], $parameters->repeated());
    }

    public function testARepetitionOfTheSameValueIsStillARepetition(): void
    {
        self::assertTrue(new RequestParameters(['scope' => ['openid', 'openid']])->isRepeated('scope'));
    }

    public function testARepeatedEmptyValueIsStillARepetition(): void
    {
        self::assertSame(['state'], new RequestParameters(['state' => ['', '']])->repeated());
    }

    public function testTheFirstValueOfARepeatedParameterIsTheOneRead(): void
    {
        // Callers refuse repetitions before reading; this only pins what "read" means.
        self::assertSame('a', new RequestParameters(['x' => ['a', 'b']])->get('x'));
    }

    public function testNamesThatLookLikeNumbersStayStrings(): void
    {
        $parameters = new RequestParameters(['123' => ['a', 'b']]);

        self::assertSame(['123'], $parameters->repeated());
        self::assertSame('a', $parameters->get('123'));
    }

    public function testTheRequestCanBeRebuiltAsAQueryWithOneParameterChanged(): void
    {
        $parameters = new RequestParameters([
            'prompt' => ['consent login'],
            'redirect_uri' => ['https://app.example/cb?a=1'],
            'state' => ['é x'],
        ]);

        self::assertSame(
            'prompt=consent%20login&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fa%3D1&state=%C3%A9%20x',
            $parameters->toQueryString(),
        );
        self::assertSame(
            'prompt=login&redirect_uri=https%3A%2F%2Fapp.example%2Fcb%3Fa%3D1&state=%C3%A9%20x',
            $parameters->with('prompt', 'login')->toQueryString(),
            'Replaced in place.',
        );
        self::assertSame(
            'state=%C3%A9%20x',
            $parameters->with('prompt', null)->with('redirect_uri', null)->toQueryString(),
        );
        self::assertSame('x=1', new RequestParameters([])->with('x', '1')->toQueryString());
        self::assertSame('consent login', $parameters->get('prompt'), 'The original is untouched.');
    }

    public function testAMapHasNoRepetition(): void
    {
        $parameters = RequestParameters::fromMap(['grant_type' => 'authorization_code', 'code' => 'abc']);

        self::assertSame('authorization_code', $parameters->get('grant_type'));
        self::assertSame('abc', $parameters->get('code'));
        self::assertSame([], $parameters->repeated());
    }
}
