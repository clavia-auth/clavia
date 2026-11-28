<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /.well-known/authzen-configuration` on `management.{domain}` (AuthZEN 1.0 §9): the decision
 * point's metadata, naming exactly the endpoints that exist (§9.1.1: an endpoint left out is one the
 * decision point does not offer). Public, as discovery is.
 */
final readonly class AuthZenMetadataHandler implements RequestHandlerInterface
{
    /** How long a client may keep it: the endpoints change only with a release. */
    public const int CACHE_MAX_AGE = 3600;

    /**
     * @param non-empty-string $origin `https://management.{domain}`: the decision point's identifier,
     *                                 which a client checks the document names (§9.2.3).
     */
    public function __construct(private string $origin)
    {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new JsonResponse(
            [
                'policy_decision_point' => $this->origin,
                'access_evaluation_endpoint' => $this->origin . '/access/v1/evaluation',
                'access_evaluations_endpoint' => $this->origin . '/access/v1/evaluations',
            ],
            StatusCodeInterface::STATUS_OK,
            ['Cache-Control' => sprintf('public, max-age=%d', self::CACHE_MAX_AGE)],
            JsonResponse::DEFAULT_JSON_FLAGS | JSON_UNESCAPED_SLASHES,
        );
    }
}
