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
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;

/**
 * Every `/scim/v2` response: `application/scim+json` (RFC 7644 §8.1), never cacheable, since every
 * answer depends on the token that asked.
 *
 * Errors are RFC 7644 §3.12 documents: `schemas`, `status` as a string, an optional `scimType`,
 * and a `detail` that names the rule broken and never repeats a value sent.
 */
final readonly class ScimResponder
{
    public const string MEDIA_TYPE = 'application/scim+json';
    public const string ERROR_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:Error';
    public const string LIST_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:ListResponse';

    private const int JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    /**
     * @param array<string, mixed>           $document
     * @param array<non-empty-string, string> $headers
     */
    public function json(
        array $document,
        int $status = StatusCodeInterface::STATUS_OK,
        array $headers = [],
    ): ResponseInterface {
        return new JsonResponse(
            $document,
            $status,
            ['Content-Type' => self::MEDIA_TYPE, 'Cache-Control' => 'no-store'] + $headers,
            self::JSON_FLAGS,
        );
    }

    /**
     * Every resource of a kind, in one page (RFC 7644 §3.4.2): a collection small by nature, such
     * as the resource types or the schemas this server supports.
     *
     * @param list<array<string, mixed>> $resources
     */
    public function listOf(array $resources): ResponseInterface
    {
        return $this->json([
            'schemas' => [self::LIST_SCHEMA],
            'totalResults' => count($resources),
            'startIndex' => 1,
            'itemsPerPage' => count($resources),
            'Resources' => $resources,
        ]);
    }

    /**
     * An error document (RFC 7644 §3.12).
     *
     * @param string                          $detail   The rule broken, never a value sent.
     * @param string|null                     $scimType One of §3.12's, for a `400` or a `409`.
     * @param array<non-empty-string, string> $headers
     */
    public function error(int $status, string $detail, ?string $scimType = null, array $headers = []): ResponseInterface
    {
        $document = ['schemas' => [self::ERROR_SCHEMA], 'status' => (string) $status];
        if ($scimType !== null) {
            $document['scimType'] = $scimType;
        }

        return $this->json($document + ['detail' => $detail], $status, $headers);
    }

    /**
     * `401` with a bearer challenge (RFC 6750 §3): `invalid_token` when a token was presented,
     * nothing more when none was (§3.1). The same document every time, whatever was wrong.
     */
    public function unauthorized(bool $tokenPresented): ResponseInterface
    {
        return $this->error(
            StatusCodeInterface::STATUS_UNAUTHORIZED,
            'A provisioning token is required, as Authorization: Bearer.',
            headers: [
                'WWW-Authenticate' => $tokenPresented
                    ? 'Bearer realm="scim", error="invalid_token"'
                    : 'Bearer realm="scim"',
            ],
        );
    }

    /** `429` (RFC 6585 §4) with `Retry-After`: too many failed tokens from this address. */
    public function tooManyFailures(int $retryAfter): ResponseInterface
    {
        return $this->error(
            StatusCodeInterface::STATUS_TOO_MANY_REQUESTS,
            'Too many requests with a wrong token from this address; try again later.',
            headers: ['Retry-After' => (string) $retryAfter],
        );
    }

    public function notFound(): ResponseInterface
    {
        return $this->error(StatusCodeInterface::STATUS_NOT_FOUND, 'No such resource.');
    }
}
