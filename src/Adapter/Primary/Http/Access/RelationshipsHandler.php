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
use Clavia\Application\Authorization\Relationships\ReadRelationships;
use Clavia\Application\Authorization\Relationships\WriteRelationships;
use Clavia\Domain\Authorization\Condition;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ObjectType;
use Clavia\Domain\Authorization\Relation;
use Clavia\Domain\Authorization\SubjectRef;
use Clavia\Domain\Authorization\Tuple;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\RequestMethodInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

/**
 * `POST|GET /access/v1/relationships` (docs/design/fine-grained-authorization.md §5.3): the
 * relationships of the calling API's own resources, in the contract's shape (`resource`, `relation`,
 * `subject`, `condition`), translated to and from the engine's tuples.
 */
final readonly class RelationshipsHandler implements RequestHandlerInterface
{
    public function __construct(
        private WriteRelationships $write,
        private ReadRelationships $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $access = AccessRequest::of($request);

        if ($request->getMethod() === RequestMethodInterface::METHOD_POST) {
            $body = $access->body();
            ($this->write)(
                $access->caller->clientId,
                self::tuples($body->writes ?? []),
                self::tuples($body->deletes ?? []),
            );

            return $this->responder->noContent();
        }

        /** @var string $object */
        $object = $access->query('object');
        /** @var mixed $size */
        $size = $access->query('page_size');
        /** @var mixed $token */
        $token = $access->query('page_token');
        $page = ($this->read)(
            $access->caller->clientId,
            ObjectRef::fromString($object),
            is_int($size) && $size > 0 ? $size : ReadRelationships::DEFAULT_PAGE_SIZE,
            is_string($token) ? $token : '',
        );

        $document = ['items' => array_map(self::document(...), $page->tuples)];
        if ($page->next !== '') {
            $document['next_page_token'] = $page->next;
        }

        return $this->responder->json($document);
    }

    /**
     * The contract checked the shape; the domain checks what OpenFGA's notation takes.
     *
     * @return list<Tuple>
     *
     * @throws InvalidValue
     */
    private static function tuples(mixed $relationships): array
    {
        $tuples = [];
        foreach (is_array($relationships) ? $relationships : [] as $relationship) {
            if (! $relationship instanceof stdClass) {
                continue;
            }
            $tuples[] = self::tuple($relationship);
        }

        return $tuples;
    }

    /** @throws InvalidValue */
    private static function tuple(stdClass $relationship): Tuple
    {
        /** @var stdClass $resource */
        $resource = $relationship->resource;
        /** @var stdClass $subject */
        $subject = $relationship->subject;
        $subjectObject = self::object($subject);
        $condition = null;
        /** @var mixed $given */
        $given = $relationship->condition ?? null;
        if ($given instanceof stdClass) {
            /** @var array<string, mixed> $context */
            $context = json_decode(
                json_encode($given->context ?? new stdClass(), JSON_THROW_ON_ERROR),
                true,
                32,
                JSON_THROW_ON_ERROR,
            );
            $condition = Condition::of((string) $given->name, $context);
        }

        return Tuple::of(
            self::object($resource),
            Relation::fromString((string) $relationship->relation),
            isset($subject->relation)
                ? SubjectRef::userset($subjectObject, Relation::fromString((string) $subject->relation))
                : SubjectRef::object($subjectObject),
            $condition,
        );
    }

    /** @throws InvalidValue */
    private static function object(stdClass $entity): ObjectRef
    {
        return ObjectRef::of(ObjectType::fromString((string) $entity->type), (string) $entity->id);
    }

    /** @return array<string, mixed> */
    private static function document(Tuple $tuple): array
    {
        $subject = ['type' => $tuple->subject->object->type->value, 'id' => $tuple->subject->object->id];
        if ($tuple->subject->relation !== null) {
            $subject['relation'] = $tuple->subject->relation->name;
        }
        $document = [
            'resource' => ['type' => $tuple->object->type->value, 'id' => $tuple->object->id],
            'relation' => $tuple->relation->name,
            'subject' => $subject,
        ];
        if ($tuple->condition !== null) {
            $document['condition'] = ['name' => $tuple->condition->name];
            if ($tuple->condition->context !== []) {
                $document['condition']['context'] = $tuple->condition->context;
            }
        }

        return $document;
    }
}
