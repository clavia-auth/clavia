<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\InitialAccessTokens\IssueInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\NewInitialAccessToken;
use Clavia\Application\Management\InitialAccessTokens\ReadInitialAccessTokens;
use Clavia\Domain\Client\Registration\InitialAccessToken;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/initial-access-tokens`: `GET` lists them (`listInitialAccessTokens`), `POST` issues one
 * (`issueInitialAccessToken`), its value in the answer, once.
 */
final readonly class InitialAccessTokensHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadInitialAccessTokens $read,
        private IssueInitialAccessToken $issue,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);

        return match ($request->getMethod()) {
            'GET' => $this->list($management),
            'POST' => $this->issue($management->body),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    private function list(ManagementRequest $management): ResponseInterface
    {
        $now = $this->read->now();

        return $this->responder->json(ManagementViews::page(
            $this->read->page(Paging::fromRequest($management)),
            static fn (InitialAccessToken $token): array => ManagementViews::initialAccessToken($token, $now),
        ));
    }

    private function issue(JsonObject $body): ResponseInterface
    {
        $issued = ($this->issue)(new NewInitialAccessToken(
            $body->string('description') ?? throw new LogicException("The contract requires 'description'."),
            $body->int('expires_in') ?? NewInitialAccessToken::DEFAULT_LIFETIME_SECONDS,
            $body->int('max_uses') ?? 1,
        ));

        return $this->responder->created(
            ManagementViews::issuedInitialAccessToken($issued, $this->read->now()),
            '/api/v1/initial-access-tokens/' . $issued->token->id->value,
        );
    }
}
