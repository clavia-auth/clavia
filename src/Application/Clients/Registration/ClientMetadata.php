<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Domain\Client\BackChannelLogout;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\Url;

/**
 * What a self-registered client may be, once {@see RegistrationMetadata} has read its request:
 * every field it is allowed to set, with its defaults filled in. Nothing else of the request is
 * kept (RFC 7591 §2: the response says what was).
 */
final readonly class ClientMetadata
{
    /**
     * @param non-empty-string    $name
     * @param list<Url>          $redirectUris
     * @param list<GrantType>    $grantTypes
     * @param list<ResponseType> $responseTypes
     * @param list<Url>          $postLogoutRedirectUris
     */
    public function __construct(
        public string $name,
        public ClientType $type,
        public ClientAuthMethod $authMethod,
        public array $redirectUris,
        public array $grantTypes,
        public array $responseTypes,
        public array $postLogoutRedirectUris,
        public ?BackChannelLogout $backChannelLogout,
        public bool $requireDpop,
    ) {
    }
}
