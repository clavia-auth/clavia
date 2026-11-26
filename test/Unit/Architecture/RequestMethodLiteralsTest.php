<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Architecture;

use Fig\Http\Message\RequestMethodInterface;
use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Methods are named (`RequestMethodInterface::METHOD_POST`, never `'POST'`) wherever a vendor may be
 * imported: the adapters, the composition root, the routes and the tests. The domain and the application
 * import none, so the one method they name, a DPoP proof's `htm`, stays a literal there.
 */
final class RequestMethodLiteralsTest extends TestCase
{
    public function testNoMethodIsWrittenAsAString(): void
    {
        // Every method the interface names, read from it rather than written here.
        $methods = array_values((new ReflectionClass(RequestMethodInterface::class))->getConstants());
        $offenders = [];
        foreach (SourceFiles::in(['config', 'public', 'src/Adapter', 'src/Bootstrap', 'test']) as $file) {
            foreach (token_get_all((string) file_get_contents($file)) as $token) {
                if (
                    is_array($token)
                    && $token[0] === T_CONSTANT_ENCAPSED_STRING
                    && in_array(substr($token[1], 1, -1), $methods, true)
                ) {
                    $offenders[] = substr($file, strlen(SourceFiles::PROJECT_ROOT) + 1) . ':' . $token[2];
                }
            }
        }

        self::assertSame([], $offenders, 'Use RequestMethodInterface::METHOD_*.');
    }
}
