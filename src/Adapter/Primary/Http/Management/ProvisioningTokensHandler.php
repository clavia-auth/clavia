<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ProvisioningTokens\IssueProvisioningToken;
use Clavia\Application\Management\ProvisioningTokens\NewProvisioningToken;
use Clavia\Application\Management\ProvisioningTokens\ReadProvisioningTokens;
use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\SubjectAttribute;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/provisioning-tokens`: `GET` lists them (`listProvisioningTokens`), `POST` issues one
 * (`issueProvisioningToken`), its value and the SCIM base URL in the answer, the value once.
 */
final readonly class ProvisioningTokensHandler implements RequestHandlerInterface
{
    /** @param non-empty-string $scimBaseUrl What a directory is configured with beside the token. */
    public function __construct(
        private ReadProvisioningTokens $read,
        private IssueProvisioningToken $issue,
        private ManagementResponder $responder,
        private string $scimBaseUrl,
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
        /** @var mixed $connection */
        $connection = $management->query('connection');

        return $this->responder->json(ManagementViews::page(
            $this->read->page(Paging::fromRequest($management), is_string($connection) ? $connection : null),
            static fn (ProvisioningToken $token): array => ManagementViews::provisioningToken($token, $now),
        ));
    }

    private function issue(JsonObject $body): ResponseInterface
    {
        $subject = $body->string('subject_attribute');
        $issued = ($this->issue)(new NewProvisioningToken(
            $body->string('connection') ?? throw new LogicException("The contract requires 'connection'."),
            $body->string('description') ?? throw new LogicException("The contract requires 'description'."),
            $body->int('expires_in') ?? ProvisioningToken::DEFAULT_LIFETIME_SECONDS,
            $subject === null ? SubjectAttribute::ExternalId : SubjectAttribute::from($subject),
            $body->bool('addresses_trusted') ?? false,
            $body->bool('delete_deactivates') ?? false,
        ));

        return $this->responder->created(
            ManagementViews::provisioningToken($issued->token, $this->read->now()) + [
                'token' => $issued->secret,
                'base_url' => $this->scimBaseUrl,
            ],
            '/api/v1/provisioning-tokens/' . $issued->token->id->value,
        );
    }
}
