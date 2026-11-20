<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Oidc;

use Clavia\Adapter\Primary\Http\Shared\BearerChallenger;
use Clavia\Adapter\Primary\Http\Shared\BearerCredentials;
use Clavia\Application\Oidc\UserInfo\ReadUserInfo;
use Clavia\Domain\OAuth2\BearerTokenError;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The userinfo endpoint (OIDC Core §5.3), on `GET` and `POST` as §5.3.1 requires.
 *
 * A protected resource: it takes a bearer access token in the `Authorization` header
 * and answers with RFC 6750 challenges. Always JSON, whatever `Accept` says, and never
 * cacheable — the answer is about one person.
 */
final readonly class UserInfoHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadUserInfo $readUserInfo,
        private BearerChallenger $challenger,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $token = BearerCredentials::fromRequest($request);
            if ($token === null) {
                return $this->challenger->missing();
            }

            $claims = ($this->readUserInfo)($token);
        } catch (BearerTokenError $error) {
            return $this->challenger->refuse($error);
        }

        return new JsonResponse(
            $claims,
            200,
            ['Cache-Control' => 'no-store'],
            JsonResponse::DEFAULT_JSON_FLAGS | JSON_UNESCAPED_SLASHES,
        );
    }
}
