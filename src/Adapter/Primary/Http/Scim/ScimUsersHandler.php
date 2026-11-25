<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Provisioning\Users\AttributeTaken;
use Clavia\Application\Provisioning\Users\CreateScimUser;
use Clavia\Application\Provisioning\Users\ProvisionedUser;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/scim/v2/Users`: `POST` creates an account (RFC 7644 §3.3), `GET` lists them with `filter`,
 * `startIndex` and `count` (§3.4.2), in the connection of the caller's token.
 */
final readonly class ScimUsersHandler implements RequestHandlerInterface
{
    /** @param non-empty-string $baseUrl */
    public function __construct(
        private CreateScimUser $create,
        private ReadScimUsers $read,
        private ScimResponder $responder,
        private string $baseUrl,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            return match ($request->getMethod()) {
                'GET' => $this->list($request),
                'POST' => $this->create($request),
                default => throw new LogicException('Routed with a method the handler does not serve.'),
            };
        } catch (ScimRequestRejected $rejection) {
            return $this->responder->error($rejection->status, $rejection->getMessage(), $rejection->scimType);
        }
    }

    private function create(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $created = ($this->create)(ScimRequest::caller($request), ScimUser::fromJson(ScimBody::read($request)));
        } catch (InvalidValue $refusal) {
            return $this->responder->error(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                $refusal->getMessage(),
                'invalidValue',
            );
        }
        if ($created instanceof AttributeTaken) {
            return $this->responder->error(
                StatusCodeInterface::STATUS_CONFLICT,
                sprintf("The '%s' is already another account's in this connection.", $created->attribute),
                'uniqueness',
            );
        }

        return $this->responder->json(
            ScimUserDocument::of($created, $this->baseUrl),
            StatusCodeInterface::STATUS_CREATED,
            [
                'Location' => ScimUserDocument::location($created->user->id->value, $this->baseUrl),
                'ETag' => ScimUserDocument::etag($created),
            ],
        );
    }

    private function list(ServerRequestInterface $request): ResponseInterface
    {
        $query = RequestParameterReader::query($request);
        if ($query->repeated() !== []) {
            throw new ScimRequestRejected(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                'A query parameter is sent once.',
                'invalidValue',
            );
        }
        $filter = $query->get('filter');
        try {
            $parsed = $filter === null ? null : ScimFilter::parse($filter);
        } catch (InvalidValue $refusal) {
            return $this->responder->error(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                $refusal->getMessage(),
                'invalidFilter',
            );
        }
        $page = $this->read->page(
            ScimRequest::caller($request),
            $parsed,
            self::integer($query->get('startIndex'), 'startIndex', 1),
            self::integer($query->get('count'), 'count', ReadScimUsers::DEFAULT_COUNT),
        );

        return $this->responder->json([
            'schemas' => [ScimResponder::LIST_SCHEMA],
            'totalResults' => $page->total,
            'startIndex' => $page->startIndex,
            'itemsPerPage' => count($page->users),
            'Resources' => array_map(
                fn (ProvisionedUser $user): array => ScimUserDocument::of($user, $this->baseUrl),
                $page->users,
            ),
        ]);
    }

    private static function integer(?string $value, string $name, int $default): int
    {
        if ($value === null) {
            return $default;
        }
        if (preg_match('/^-?\d{1,9}$/D', $value) !== 1) {
            throw new ScimRequestRejected(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                sprintf("'%s' is an integer.", $name),
                'invalidValue',
            );
        }

        return (int) $value;
    }
}
