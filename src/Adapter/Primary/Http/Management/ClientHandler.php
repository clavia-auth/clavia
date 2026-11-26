<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Clients\ClientChanges;
use Clavia\Application\Management\Clients\DeleteClient;
use Clavia\Application\Management\Clients\ReadClients;
use Clavia\Application\Management\Clients\UpdateClient;
use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/clients/{client_id}`: `GET` (`getClient`), `PATCH` (`updateClient`),
 * `DELETE` (`deleteClient`).
 */
final readonly class ClientHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadClients $read,
        private UpdateClient $update,
        private DeleteClient $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = ClientId::fromString($management->path('client_id'));

        switch ($request->getMethod()) {
            case RequestMethodInterface::METHOD_GET:
                return $this->responder->json(ManagementViews::client($this->read->one($id)));
            case RequestMethodInterface::METHOD_PATCH:
                $body = $management->body;
                $claims = self::claims($body);
                if ($claims instanceof Problem) {
                    return $this->responder->problem($claims);
                }

                $updated = ($this->update)($id, new ClientChanges(
                    $body->string('name'),
                    $body->string('token_endpoint_auth_method'),
                    $body->strings('redirect_uris'),
                    $body->strings('grant_types'),
                    $body->strings('response_types'),
                    $body->strings('post_logout_redirect_uris'),
                    $body->has('backchannel_logout_uri'),
                    $body->string('backchannel_logout_uri'),
                    $body->bool('backchannel_logout_session_required'),
                    $body->bool('require_pkce'),
                    $body->string('mfa_policy'),
                    $body->bool('require_pushed_authorization_requests'),
                    $body->bool('dpop_bound_access_tokens'),
                    $claims,
                    $body->has('accent_color'),
                    $body->string('accent_color'),
                ));

                return $this->responder->json(ManagementViews::client($this->read->describe($updated)));
            case RequestMethodInterface::METHOD_DELETE:
                ($this->delete)($id, $management->caller);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }

    /**
     * The `claims` of the body as an application's mappings; null when absent; a problem pointing
     * at each entry the domain refuses (`/claims/2`), or at `/claims` for the list as a whole.
     */
    private static function claims(JsonObject $body): ClaimMappings|Problem|null
    {
        $entries = $body->objects('claims');
        if ($entries === null) {
            return null;
        }
        $mappings = [];
        $errors = [];
        foreach ($entries as $index => $entry) {
            try {
                $mappings[] = ClaimMapping::forApplication(
                    ClaimName::fromString((string) $entry->string('name'), onAnApi: false),
                    ClaimSource::fromString((string) $entry->string('source'), $entry->encoded('value')),
                    ClaimMappings::destinations($entry->strings('in')),
                );
            } catch (InvalidValue $refusal) {
                $errors[] = ['pointer' => '/claims/' . $index, 'detail' => $refusal->getMessage()];
            }
        }
        try {
            return $errors === []
                ? ClaimMappings::of($mappings)
                : new Problem(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, ContractViolation::DETAIL, $errors);
        } catch (InvalidValue $refusal) {
            return new Problem(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                ContractViolation::DETAIL,
                [['pointer' => '/claims', 'detail' => $refusal->getMessage()]],
            );
        }
    }
}
