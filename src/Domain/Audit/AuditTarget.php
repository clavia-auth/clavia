<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Rbac\RoleId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Webhook\WebhookEndpointId;

/**
 * The thing an audit event was about, by type and identifier: the account signed in to,
 * the client changed, the role given. Kept as text — the thing may be gone by the time the
 * trail is read, and the trail must not go with it.
 */
final readonly class AuditTarget
{
    /**
     * @param non-empty-string $id
     */
    private function __construct(
        public TargetType $type,
        public string $id,
    ) {
    }

    /**
     * @throws InvalidValue When the identifier is empty or longer than 255 characters.
     */
    public static function of(TargetType $type, string $id): self
    {
        if ($id === '' || strlen($id) > 255) {
            throw new InvalidValue('An audit target is named by 1 to 255 characters.');
        }

        return new self($type, $id);
    }

    public static function user(UserId $id): self
    {
        return self::of(TargetType::User, $id->value);
    }

    public static function client(ClientId $id): self
    {
        return self::of(TargetType::Client, $id->value);
    }

    public static function resourceServer(ResourceServerId $id): self
    {
        return self::of(TargetType::ResourceServer, $id->value);
    }

    public static function role(RoleId $id): self
    {
        return self::of(TargetType::Role, $id->value);
    }

    public static function connection(ConnectionName $name): self
    {
        return self::of(TargetType::Connection, $name->value);
    }

    /** @param non-empty-string $kid */
    public static function signingKey(string $kid): self
    {
        return self::of(TargetType::SigningKey, $kid);
    }

    /** A SAML service provider key, by its kid: the signing key of a pair names the pair. */
    public static function samlKey(string $kid): self
    {
        return self::of(TargetType::SamlKey, $kid);
    }

    public static function initialAccessToken(InitialAccessTokenId $id): self
    {
        return self::of(TargetType::InitialAccessToken, $id->value);
    }

    public static function provisioningToken(ProvisioningTokenId $id): self
    {
        return self::of(TargetType::ProvisioningToken, $id->value);
    }

    public static function webhook(WebhookEndpointId $id): self
    {
        return self::of(TargetType::Webhook, $id->value);
    }
}
