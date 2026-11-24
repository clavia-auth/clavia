<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Shared;

use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Answers an error in the form the caller can use: a page for a person in a browser, a
 * JSON document for a program ({@see ClientPreference}).
 *
 * The two say the same thing at the same status with the same headers; only the body
 * differs. The page is written for the person — what happened and what to do next — and
 * never offers a way onwards that the request itself supplied: nothing in an error page
 * links to an address an unvalidated request named.
 */
final readonly class ErrorResponder
{
    public function __construct(private PageRenderer $pages)
    {
    }

    /**
     * @param array<string, mixed>  $document The JSON body for a program.
     * @param array<non-empty-string, string> $headers Sent with either form (`Allow`, `Cache-Control`…).
     */
    public function respond(
        ServerRequestInterface $request,
        int $status,
        ErrorPage $page,
        array $document,
        array $headers = [],
    ): ResponseInterface {
        if (! ClientPreference::prefersHtml($request)) {
            return new JsonResponse($document, $status, $headers);
        }

        $response = $this->pages->render($request, $page->toHtmlPage($status));

        foreach ($headers as $name => $value) {
            $response = $response->withHeader($name, $value);
        }

        return $response;
    }

    /** No route matches the path. */
    public function notFound(ServerRequestInterface $request): ResponseInterface
    {
        return $this->respond(
            $request,
            StatusCodeInterface::STATUS_NOT_FOUND,
            ErrorPage::notFound(),
            ['detail' => 'Not Found'],
        );
    }

    /**
     * The path is routed, but not for this method (RFC 9110 §15.5.6).
     *
     * @param list<string> $allowed
     */
    public function methodNotAllowed(ServerRequestInterface $request, array $allowed): ResponseInterface
    {
        return $this->respond(
            $request,
            StatusCodeInterface::STATUS_METHOD_NOT_ALLOWED,
            ErrorPage::methodNotAllowed(),
            ['detail' => 'Method Not Allowed'],
            ['Allow' => implode(', ', $allowed)],
        );
    }
}
