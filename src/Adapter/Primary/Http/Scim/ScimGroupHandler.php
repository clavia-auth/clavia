<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Application\Provisioning\Groups\DeleteScimGroup;
use Clavia\Application\Provisioning\Groups\PatchScimGroup;
use Clavia\Application\Provisioning\Groups\ReadScimGroups;
use Clavia\Application\Provisioning\Groups\ReplaceScimGroup;
use Clavia\Application\Provisioning\Users\AttributeTaken;
use Clavia\Application\Provisioning\Users\VersionMismatch;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Provisioning\ScimPatch;
use Clavia\Domain\Provisioning\ScimPatchRefused;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/scim/v2/Groups/{id}`, a group of the caller's connection: `GET` reads it, `PUT` replaces it,
 * `PATCH` changes it (membership above all), `DELETE` removes it; versions as for users (RFC 7644
 * §3.14). Any other id, another connection's group included, is `404`.
 */
final readonly class ScimGroupHandler implements RequestHandlerInterface
{
    private const int BAD_REQUEST = StatusCodeInterface::STATUS_BAD_REQUEST;

    /** @param non-empty-string $baseUrl */
    public function __construct(
        private ReadScimGroups $read,
        private ReplaceScimGroup $replace,
        private PatchScimGroup $patch,
        private DeleteScimGroup $delete,
        private ScimResponder $responder,
        private string $baseUrl,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var mixed $id */
        $id = $request->getAttribute('id');
        if (! is_string($id)) {
            throw new LogicException('Routed without an id.');
        }
        $caller = ScimRequest::caller($request);
        $ifMatch = ScimUserHandler::ifMatch($request);
        try {
            $query = ScimQuery::of($request);
            $outcome = match ($request->getMethod()) {
                'GET' => $this->read->find($caller, $id),
                'PUT' => ($this->replace)(
                    $caller,
                    $id,
                    ScimGroupResource::fromJson(ScimBody::read($request)),
                    $ifMatch,
                ),
                'PATCH' => ($this->patch)($caller, $id, ScimPatch::fromJson(ScimBody::read($request)), $ifMatch),
                'DELETE' => ($this->delete)($caller, $id, $ifMatch),
                default => throw new LogicException('Routed with a method the handler does not serve.'),
            };
        } catch (ScimRequestRejected $rejection) {
            return $this->responder->error($rejection->status, $rejection->getMessage(), $rejection->scimType);
        } catch (ScimPatchRefused $refusal) {
            return $this->responder->error(self::BAD_REQUEST, $refusal->getMessage(), $refusal->scimType);
        } catch (InvalidValue $refusal) {
            return $this->responder->error(self::BAD_REQUEST, $refusal->getMessage(), 'invalidValue');
        }

        return match (true) {
            $outcome === null => $this->responder->notFound(),
            $outcome instanceof VersionMismatch => $this->responder->error(
                StatusCodeInterface::STATUS_PRECONDITION_FAILED,
                'The resource changed since the version named in If-Match.',
            ),
            $outcome instanceof AttributeTaken => $this->responder->error(
                StatusCodeInterface::STATUS_CONFLICT,
                sprintf("The '%s' is already another group's in this connection.", $outcome->attribute),
                'uniqueness',
            ),
            $request->getMethod() === 'DELETE' => $this->responder->noContent(),
            default => $this->responder->json(
                ScimGroupDocument::of($outcome, $this->baseUrl, ! $query->excludes('members')),
                headers: ['ETag' => ScimGroupDocument::etag($outcome)],
            ),
        };
    }
}
