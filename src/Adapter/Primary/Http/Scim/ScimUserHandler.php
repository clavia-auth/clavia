<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Application\Provisioning\Users\AttributeTaken;
use Clavia\Application\Provisioning\Users\DeleteScimUser;
use Clavia\Application\Provisioning\Users\PatchScimUser;
use Clavia\Application\Provisioning\Users\ProvisionedUser;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Application\Provisioning\Users\ReplaceScimUser;
use Clavia\Application\Provisioning\Users\VersionMismatch;
use Clavia\Domain\Provisioning\ScimPatch;
use Clavia\Domain\Provisioning\ScimPatchRefused;
use Clavia\Domain\Provisioning\ScimUser;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/scim/v2/Users/{id}`, an account of the caller's connection: `GET` reads it (RFC 7644 §3.4.1),
 * `PUT` replaces it (§3.5.1), `PATCH` modifies it (§3.5.2), `DELETE` removes it (§3.6). Any other id,
 * another connection's account included, is `404` (docs/design/scim-provisioning.md §7).
 *
 * Every resource answered carries its version as a weak ETag (§3.14), and a change honours
 * `If-Match`: a version that is no longer the resource's is `412`.
 */
final readonly class ScimUserHandler implements RequestHandlerInterface
{
    private const int BAD_REQUEST = StatusCodeInterface::STATUS_BAD_REQUEST;

    /** @param non-empty-string $baseUrl */
    public function __construct(
        private ReadScimUsers $read,
        private ReplaceScimUser $replace,
        private PatchScimUser $patch,
        private DeleteScimUser $delete,
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
        $ifMatch = self::ifMatch($request);
        try {
            $outcome = match ($request->getMethod()) {
                'GET' => $this->read->find($caller, $id),
                'PUT' => ($this->replace)($caller, $id, ScimUser::fromJson(ScimBody::read($request)), $ifMatch),
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
                sprintf("The '%s' is already another account's in this connection.", $outcome->attribute),
                'uniqueness',
            ),
            $outcome instanceof ProvisionedUser => $this->responder->json(
                ScimUserDocument::of($outcome, $this->baseUrl),
                headers: ['ETag' => ScimUserDocument::etag($outcome)],
            ),
            default => $this->responder->noContent(),
        };
    }

    /**
     * The versions `If-Match` names (RFC 9110 §13.1.1): `*`, or entity tags, weak or strong alike, as
     * SCIM's own are weak (RFC 7644 §3.14). Null without the header.
     *
     * @return list<string>|null
     */
    public static function ifMatch(ServerRequestInterface $request): ?array
    {
        if (! $request->hasHeader('If-Match')) {
            return null;
        }
        $versions = [];
        foreach (explode(',', $request->getHeaderLine('If-Match')) as $tag) {
            $tag = trim($tag);
            if ($tag === '*') {
                $versions[] = '*';
            } elseif (preg_match('/^(?:W\/)?"([^"]*)"$/D', $tag, $match) === 1) {
                $versions[] = $match[1];
            }
        }

        return $versions;
    }
}
