<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use JsonException;
use Psr\Http\Message\ServerRequestInterface;
use stdClass;

/**
 * Reads client metadata as RFC 7591 §3 and RFC 7592 §2.2 send it: a JSON object, member by
 * member.
 */
final class ClientMetadataBody
{
    private function __construct()
    {
    }

    /**
     * The body's members: a JSON object, sent as `application/json` (RFC 7591 §3). Anything else
     * is read as no member at all, which the policy refuses for want of a `client_name` (or, at
     * an update, of a `client_id`).
     *
     * @return array<array-key, mixed>
     */
    public static function members(ServerRequestInterface $request): array
    {
        $type = strtolower(trim(explode(';', $request->getHeaderLine('Content-Type'))[0]));
        if ($type !== 'application/json') {
            return [];
        }
        try {
            /** @var mixed $body */
            $body = json_decode((string) $request->getBody(), false, 32, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return [];
        }

        return $body instanceof stdClass ? get_object_vars($body) : [];
    }
}
