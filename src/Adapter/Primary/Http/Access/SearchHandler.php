<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Access;

use Clavia\Adapter\Primary\Http\Management\ManagementResponder;
use Clavia\Application\Authorization\Search\SearchAccess;
use Clavia\Application\Authorization\Search\SearchKind;
use Clavia\Application\Authorization\Search\SearchRequest;
use Clavia\Application\Authorization\Search\SearchResults;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

/**
 * `POST /access/v1/search/subject`, `/search/resource` and `/search/action` (AuthZEN 1.0 §8): the
 * AuthZEN shapes, translated to and from {@see SearchAccess}. The id of the entity searched for is
 * ignored if sent (§8.4.1, §8.5.1), as are members AuthZEN does not define (§10.1.1). Every answer
 * carries `page` first (§8.3), its `next_token` empty after the last page (§8.2.2).
 */
final readonly class SearchHandler implements RequestHandlerInterface
{
    /** A page when `page.limit` is not given. */
    public const int DEFAULT_LIMIT = 50;

    public function __construct(
        private SearchAccess $search,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $access = AccessRequest::of($request);
        $body = $access->body();
        $path = $request->getUri()->getPath();
        $kind = match (true) {
            str_ends_with($path, '/subject') => SearchKind::Subject,
            str_ends_with($path, '/resource') => SearchKind::Resource,
            default => SearchKind::Action,
        };
        $subject = self::object($body, 'subject');
        $resource = self::object($body, 'resource');
        $page = self::object($body, 'page');
        /** @var mixed $limit */
        $limit = $page->limit ?? null;
        $search = new SearchRequest(
            self::string($subject, 'type'),
            $kind === SearchKind::Subject ? '' : self::string($subject, 'id'),
            self::string(self::object($body, 'action'), 'name'),
            self::string($resource, 'type'),
            $kind === SearchKind::Resource ? '' : self::string($resource, 'id'),
            AccessRequest::members(self::object($body, 'context')),
            is_int($limit) && $limit > 0 ? $limit : self::DEFAULT_LIMIT,
            self::string($page, 'token'),
        );

        $results = match ($kind) {
            SearchKind::Subject => $this->search->subjects($access->caller->clientId, $search),
            SearchKind::Resource => $this->search->resources($access->caller->clientId, $search),
            SearchKind::Action => $this->search->actions($access->caller->clientId, $search),
        };

        return $this->responder->json(self::document($results, $kind, $search));
    }

    /** @return array<string, mixed> */
    private static function document(SearchResults $results, SearchKind $kind, SearchRequest $search): array
    {
        $document = [
            'page' => ['next_token' => $results->nextToken, 'count' => count($results->ids)],
            'results' => array_map(
                static fn (string $id): array => match ($kind) {
                    SearchKind::Subject => ['type' => $search->subjectType, 'id' => $id],
                    SearchKind::Resource => ['type' => $search->resourceType, 'id' => $id],
                    SearchKind::Action => ['name' => $id],
                },
                $results->ids,
            ),
        ];
        if ($results->error !== null) {
            $document['context'] = ['error' => ['status' => 400, 'message' => $results->error]];
        }

        return $document;
    }

    private static function object(stdClass $body, string $name): stdClass
    {
        /** @var mixed $value */
        $value = $body->{$name} ?? null;

        return $value instanceof stdClass ? $value : new stdClass();
    }

    private static function string(stdClass $object, string $name): string
    {
        /** @var mixed $value */
        $value = $object->{$name} ?? null;

        return is_string($value) ? $value : '';
    }
}
