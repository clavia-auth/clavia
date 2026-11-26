<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Validation\FormBody;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\Violation;
use PHPUnit\Framework\TestCase;

/** A form body (WHATWG URL §5.1) read as named strings, each sent once (RFC 6749 §3.1). */
final class FormBodyTest extends TestCase
{
    public function testFieldsAreDecodedAndKeptAsSent(): void
    {
        $form = FormBody::read(
            'grant_type=client_credentials&scope=read%3Ausers+read%3Aclients&a.b=1&c%5B%5D=2&empty=',
        );

        self::assertSame([], $form->malformed);
        self::assertSame([
            'grant_type' => 'client_credentials',
            'scope' => 'read:users read:clients',
            'a.b' => '1',
            'c[]' => '2',
            'empty' => '',
        ], get_object_vars($form->values), 'Names as sent: no parse_str() rewriting.');
    }

    public function testAnEmptyBodyIsAnEmptyForm(): void
    {
        self::assertSame([], get_object_vars(FormBody::read('')->values));
        self::assertSame([], get_object_vars(FormBody::read('&&')->values));
    }

    public function testAFieldSentTwiceIsReportedAtItsPointerAndNothingIsKept(): void
    {
        $form = FormBody::read('code=a&scope=x&code=b&a%2Fb=1&a%2Fb=2');

        self::assertEquals([
            Violation::inBody('/code', 'Is sent more than once.'),
            Violation::inBody('/a~1b', 'Is sent more than once.'),
        ], $form->malformed);
        self::assertSame([], get_object_vars($form->values), 'A malformed form hands nothing on.');
    }

    public function testAValueThatIsNotUtf8IsMalformed(): void
    {
        self::assertEquals(
            [Violation::inBody('', 'Is not valid UTF-8.')],
            FormBody::read('name=%E9t%E9')->malformed,
        );
    }
}
