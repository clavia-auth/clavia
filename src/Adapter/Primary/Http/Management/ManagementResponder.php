<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Every Management API response that is not a bearer challenge: JSON documents, `201`
 * with `Location`, `204`, and RFC 9457 problem documents.
 *
 * Nothing the Management API says may be cached — every answer depends on the token
 * that asked — so each response carries `Cache-Control: no-store`.
 */
final readonly class ManagementResponder
{
    private const int JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    private const array NO_STORE = ['Cache-Control' => 'no-store'];

    public function __construct(private ResponseFactoryInterface $responses)
    {
    }

    /**
     * @param array<string, mixed> $document
     */
    public function json(array $document, int $status = 200): ResponseInterface
    {
        return new JsonResponse($document, $status, self::NO_STORE, self::JSON_FLAGS);
    }

    /**
     * A JSON array: a collection small enough by nature to be sent whole, such as the
     * roles of one account.
     *
     * @param list<array<string, mixed>> $items
     */
    public function jsonList(array $items): ResponseInterface
    {
        return new JsonResponse($items, 200, self::NO_STORE, self::JSON_FLAGS);
    }

    /**
     * @param array<string, mixed> $document
     * @param string               $location Where the new resource is read: an absolute path.
     */
    public function created(array $document, string $location): ResponseInterface
    {
        return $this->json($document, 201)->withHeader('Location', $location);
    }

    public function noContent(): ResponseInterface
    {
        return $this->responses->createResponse(204)->withHeader('Cache-Control', 'no-store');
    }

    public function problem(Problem $problem): ResponseInterface
    {
        $document = [
            'type' => 'about:blank',
            'title' => $this->responses->createResponse($problem->status)->getReasonPhrase(),
            'status' => $problem->status,
            'detail' => $problem->detail,
        ];
        if ($problem->errors !== []) {
            $document['errors'] = $problem->errors;
        }

        return new JsonResponse(
            $document,
            $problem->status,
            self::NO_STORE + ['Content-Type' => 'application/problem+json'],
            self::JSON_FLAGS,
        );
    }
}
