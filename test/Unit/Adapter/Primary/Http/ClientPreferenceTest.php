<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http;

use Clavia\Adapter\Primary\Http\Shared\ClientPreference;
use Laminas\Diactoros\ServerRequest;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientPreferenceTest extends TestCase
{
    #[DataProvider('browsers')]
    public function testABrowserNavigatingToAPageGetsHtml(string $accept): void
    {
        self::assertTrue(ClientPreference::prefersHtml(new ServerRequest(headers: ['Accept' => $accept])));
    }

    /** @return iterable<string, array{string}> */
    public static function browsers(): iterable
    {
        yield 'Chromium' => [
            'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
            . 'application/signed-exchange;v=b3;q=0.7',
        ];
        yield 'Firefox' => ['text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'];
        yield 'Safari' => ['text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'];
        yield 'XHTML only' => ['application/xhtml+xml'];
        yield 'any text' => ['text/*'];
        yield 'HTML preferred over JSON' => ['application/json;q=0.5, text/html'];
        yield 'a tie goes to the page' => ['text/html, application/json'];
        yield 'odd spacing and case' => [' Text/HTML ; q=1 , */* ;q=0.1'];
    }

    #[DataProvider('programs')]
    public function testAProgramGetsData(?string $accept): void
    {
        $headers = $accept === null ? [] : ['Accept' => $accept];

        self::assertFalse(ClientPreference::prefersHtml(new ServerRequest(headers: $headers)));
    }

    /** @return iterable<string, array{string|null}> */
    public static function programs(): iterable
    {
        yield 'no Accept at all' => [null];
        yield 'an empty Accept' => [''];
        yield 'curl, fetch() and most libraries' => ['*/*'];
        yield 'axios' => ['application/json, text/plain, */*'];
        yield 'JSON asked for' => ['application/json'];
        yield 'JSON preferred over HTML' => ['application/json, text/html;q=0.9'];
        yield 'HTML refused' => ['text/html;q=0, */*'];
        yield 'any application type' => ['application/*'];
        yield 'garbage' => ['not a media type, ;;;'];
        yield 'an out-of-range weight is not a preference' => ['text/html;q=2, application/json'];
    }
}
