<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Logout;

/**
 * A live session, and nothing proving the request comes from an application acting
 * for its person: the person is asked (RP-Initiated Logout 1.0 §2, "the OP SHOULD ask
 * the End-User whether to log out"). What is carried to the confirmation has been
 * checked already — an unregistered URI is not carried at all.
 */
final readonly class SignOutConfirmationNeeded
{
    /**
     * @param string|null $clientId              The application identified, if any.
     * @param string|null $clientName            Its name, for the question.
     * @param string|null $postLogoutRedirectUri A registered post-logout redirect URI, if one was asked for.
     */
    public function __construct(
        public ?string $clientId,
        public ?string $clientName,
        public ?string $postLogoutRedirectUri,
        public ?string $state,
    ) {
    }

    /** The origin the browser leaves for once confirmed, if it leaves this server. */
    public function destinationOrigin(): ?string
    {
        if ($this->postLogoutRedirectUri === null) {
            return null;
        }
        $parts = parse_url($this->postLogoutRedirectUri);

        return isset($parts['scheme'], $parts['host'])
            ? $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '')
            : null;
    }
}
