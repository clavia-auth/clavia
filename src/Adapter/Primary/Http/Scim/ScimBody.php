<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Fig\Http\Message\StatusCodeInterface;
use JsonException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;

/**
 * Reads a SCIM request's body (docs/design/scim-provisioning.md §5.2): `application/scim+json`
 * (RFC 7644 §8.1), or `application/json`, which clients also send; at most 1 MiB; one JSON object.
 */
final class ScimBody
{
    public const int MAX_BYTES = 1_048_576;

    private const int MAX_DEPTH = 32;

    private function __construct()
    {
    }

    /**
     * @throws ScimRequestRejected `413` past the size; `400 invalidSyntax` for another media type, or
     *                             anything but a JSON object.
     */
    public static function read(ServerRequestInterface $request): stdClass
    {
        $mediaType = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'), 2)[0]));
        if ($mediaType !== ScimResponder::MEDIA_TYPE && $mediaType !== 'application/json') {
            throw new ScimRequestRejected(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                'The body is application/scim+json.',
                'invalidSyntax',
            );
        }
        $body = $request->getBody();
        $content = $body->read(self::MAX_BYTES + 1);
        if (strlen($content) > self::MAX_BYTES) {
            throw new ScimRequestRejected(
                StatusCodeInterface::STATUS_PAYLOAD_TOO_LARGE,
                'The body is at most 1 MiB.',
            );
        }
        while (! $body->eof() && strlen($content) <= self::MAX_BYTES) {
            $content .= $body->read(8192);
        }
        try {
            /** @var mixed $document */
            $document = json_decode($content, false, self::MAX_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            $document = null;
        }
        if (! $document instanceof stdClass) {
            throw new ScimRequestRejected(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                'The body is one JSON object.',
                'invalidSyntax',
            );
        }

        return $document;
    }
}
