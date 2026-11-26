<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Primary\Http\OpenApi\Document;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseDoesNotMatch;
use Clavia\Adapter\Primary\Http\OpenApi\Validation\ResponseValidator;
use PHPUnit\Framework\Assert;
use Psr\Http\Message\ResponseInterface;

/**
 * `docs/openapi/authorization-server.yaml`, held against what the server answers (#93): every acceptance
 * request to a documented operation on `auth.{domain}` has its response checked, so the suite that proves
 * the endpoints' behaviour proves the document too.
 *
 * The document describes; it never gates. Requests are not checked: tests send malformed ones on purpose,
 * and the server answers those in RFC 6749's shapes, which is what the responses' check covers.
 */
final class AuthorizationServerContract
{
    public const string PATH = __DIR__ . '/../../docs/openapi/authorization-server.yaml';

    private static ?Document $document = null;

    private function __construct()
    {
    }

    public static function document(): Document
    {
        return self::$document ??= Document::fromYamlFile(self::PATH);
    }

    /** Fails the test when the document describes this operation and not this answer. */
    public static function assertDescribes(string $method, string $path, ResponseInterface $response): void
    {
        $match = self::document()->match($method, $path);
        if ($match === null) {
            return;
        }

        try {
            ResponseValidator::validate($match->operation, $response);
        } catch (ResponseDoesNotMatch $mismatch) {
            Assert::fail($mismatch->getMessage() . "\n" . substr((string) $response->getBody(), 0, 500));
        }
    }
}
