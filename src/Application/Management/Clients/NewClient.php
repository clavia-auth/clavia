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
     * @param string       $mfaPolicy     `optional` or `required`: whether its users must sign in with more
     *                                    than one factor ({@see \Clavia\Domain\Authentication\MfaPolicy}).
     * @param bool         $requirePushedAuthorizationRequests Whether its authorization requests must be
     *                                    pushed first (RFC 9126 §6).
     * @param bool         $requireDpop   Whether every token it is issued must be bound to a DPoP key
     *                                    (`dpop_bound_access_tokens`, RFC 9449 §5.2).
     * @param string|null  $accentColor   Its colour on the sign-in pages, `#` and six hexadecimal digits;
     *                                    null for this server's.
     * @param string|null  $initiateLoginUri Where it starts a sign-in of its own (`initiate_login_uri`, OpenID
     *                                    Connect Dynamic Client Registration 1.0 §2): where a person whose
     *                                    request expired is sent to start again; null for none.
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
        public string $mfaPolicy = 'optional',
        public bool $requirePushedAuthorizationRequests = false,
        public bool $requireDpop = false,
        public ?string $accentColor = null,
        public ?string $initiateLoginUri = null,
    ) {
    }
}
