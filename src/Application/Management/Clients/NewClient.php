<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

/**
 * A client to register. The id and the secret are not here: both are generated.
 */
final readonly class NewClient
{
    /**
     * @param string|null  $authMethod    Defaults to `none` for a public client, `client_secret_basic`
     *                                    for a confidential one.
     * @param list<string> $redirectUris
     * @param list<string> $grantTypes
     * @param list<string> $responseTypes
     * @param list<string> $postLogoutRedirectUris
     * @param bool         $firstParty    Whether the operator runs it. False registers a third-party
     *                                    application: its id starts with `tpc_`, every scope it asks for
     *                                    goes to the consent screen, and it never reaches a system API.
     *                                    Fixed for good.
     * @param list<string>|null $connections The connections its users may sign in through; null for every
     *                                       one there is, or none for a third-party application.
     * @param string|null  $backChannelLogoutUri Where to tell it that a session it signed in through ended.
     * @param bool         $requirePkce   False lets a confidential client's OpenID Connect requests carrying a
     *                                    `nonce` go without PKCE (OAuth 2.1 §7.5.1).
     */
    public function __construct(
        public string $name = '',
        public string $type = 'public',
        public ?string $authMethod = null,
        public array $redirectUris = [],
        public array $grantTypes = [],
        public array $responseTypes = [],
        public array $postLogoutRedirectUris = [],
        public bool $firstParty = true,
        public ?array $connections = null,
        public ?string $backChannelLogoutUri = null,
        public bool $backChannelLogoutSessionRequired = false,
        public bool $requirePkce = true,
    ) {
    }
}
