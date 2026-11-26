<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Connections\CreateConnection;
use Clavia\Application\Management\Connections\NewConnection;
use Clavia\Application\Management\Connections\NewSamlConnection;
use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\Connections\SamlMetadataRefused;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\Saml\SamlOptions;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/connections`: `GET` lists them (`listConnections`) — few by nature, so an
 * array, not a page — and `POST` creates a pool or registers a provider (`createConnection`).
 */
final readonly class ConnectionsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadConnections $read,
        private CreateConnection $create,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $body = ManagementRequest::of($request)->body;

        return match ($request->getMethod()) {
            RequestMethodInterface::METHOD_GET => $this->responder->jsonList(
                array_map(ManagementViews::connection(...), $this->read->all()),
            ),
            RequestMethodInterface::METHOD_POST => $this->create($body),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    /** A `422` pointing at the field the metadata came in (§5.2): never its content. */
    public static function metadataProblem(SamlMetadataRefused $refused): Problem
    {
        return new Problem(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            ContractViolation::DETAIL,
            [['pointer' => $refused->pointer, 'detail' => $refused->getMessage()]],
        );
    }

    private function create(JsonObject $body): ResponseInterface
    {
        try {
            $saml = self::saml($body);
        } catch (InvalidValue $refused) {
            return $this->responder->problem(new Problem(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                ContractViolation::DETAIL,
                [['pointer' => '/saml', 'detail' => $refused->getMessage()]],
            ));
        }
        try {
            $connection = $this->createConnection($body, $saml);
        } catch (SamlMetadataRefused $refused) {
            return $this->responder->problem(self::metadataProblem($refused));
        }

        return $this->responder->created(
            ManagementViews::connection($this->read->describe($connection)),
            '/api/v1/connections/' . $connection->name->value,
        );
    }

    /**
     * The `saml` of the body; null when absent.
     *
     * @throws InvalidValue When an option is refused.
     */
    private static function saml(JsonObject $body): ?NewSamlConnection
    {
        $object = $body->object('saml');
        if ($object === null) {
            return null;
        }

        return new NewSamlConnection(
            $object->string('metadata'),
            $object->string('metadata_url'),
            SamlOptions::of(
                $object->string('subject_attribute'),
                $object->string('name_id_format'),
                $object->string('email_attribute'),
                $object->bool('email_trusted') ?? false,
                $object->string('name_attribute'),
                $object->string('given_name_attribute'),
                $object->string('family_name_attribute'),
                $object->bool('sign_requests') ?? true,
                $object->bool('require_encryption') ?? false,
                $object->bool('require_gcm') ?? true,
            ),
        );
    }

    private function createConnection(JsonObject $body, ?NewSamlConnection $saml): Connection
    {
        return ($this->create)(new NewConnection(
            $body->string('name') ?? throw new LogicException("The contract requires 'name'."),
            $body->string('display_name') ?? throw new LogicException("The contract requires 'display_name'."),
            $body->string('strategy') ?? throw new LogicException("The contract requires 'strategy'."),
            $body->bool('is_enabled') ?? true,
            $body->bool('is_domain_connection') ?? false,
            $body->string('oidc_issuer'),
            $body->string('oidc_client_id'),
            $body->string('oidc_client_secret'),
            $body->string('oidc_scope'),
            $body->bool('allow_sign_up') ?? false,
            $body->bool('require_verified_email') ?? false,
            $saml,
            $body->bool('require_provisioning') ?? false,
        ));
    }
}
