<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\BreachedPasswords\PwnedPasswordsRange;
use Laminas\Diactoros\Response\TextResponse;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Have I Been Pwned's range API as a {@see FakeHttpClient} handler: for
 * `GET /range/{prefix}`, the suffix and count of every known password under that prefix,
 * among padding entries counted 0, CRLF-separated, as the service answers.
 */
final class PwnedPasswordsService
{
    private function __construct()
    {
    }

    /**
     * @param list<string> $breached
     *
     * @return callable(RequestInterface): ResponseInterface
     */
    public static function knowing(array $breached): callable
    {
        return static function (RequestInterface $request) use ($breached): ResponseInterface {
            $prefix = substr($request->getUri()->getPath(), strlen('/range/'));
            $lines = [];
            foreach ($breached as $password) {
                $hash = PwnedPasswordsRange::hashOf($password);
                if (str_starts_with($hash, $prefix)) {
                    $lines[] = substr($hash, 5) . ':' . 42;
                }
            }
            // Padding: suffixes nobody has seen.
            $lines[] = str_repeat('0', 35) . ':0';
            $lines[] = str_repeat('F', 35) . ':0';

            return new TextResponse(implode("\r\n", $lines));
        };
    }
}
