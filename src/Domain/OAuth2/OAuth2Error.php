<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use DomainException;

/**
 * The protocol says no.
 *
 * Carries the registered error code and a description written for the developer of the
 * client, never for an end user and never containing a secret. How the refusal travels —
 * a JSON body, a redirect back to the client, a `WWW-Authenticate` challenge — is the
 * primary adapter's business; which code applies is decided here, by the rule that was
 * broken.
 */
final class OAuth2Error extends DomainException
{
    private function __construct(
        public readonly ErrorCode $error,
        public readonly string $description,
    ) {
        parent::__construct($error->value . ': ' . $description);
    }

    public static function invalidRequest(string $description): self
    {
        return new self(ErrorCode::InvalidRequest, $description);
    }

    public static function invalidClient(string $description): self
    {
        return new self(ErrorCode::InvalidClient, $description);
    }

    public static function invalidGrant(string $description): self
    {
        return new self(ErrorCode::InvalidGrant, $description);
    }

    public static function unauthorizedClient(string $description): self
    {
        return new self(ErrorCode::UnauthorizedClient, $description);
    }

    public static function unsupportedGrantType(string $description): self
    {
        return new self(ErrorCode::UnsupportedGrantType, $description);
    }

    public static function unsupportedResponseType(string $description): self
    {
        return new self(ErrorCode::UnsupportedResponseType, $description);
    }

    public static function invalidScope(string $description): self
    {
        return new self(ErrorCode::InvalidScope, $description);
    }

    public static function invalidTarget(string $description): self
    {
        return new self(ErrorCode::InvalidTarget, $description);
    }

    public static function accessDenied(string $description): self
    {
        return new self(ErrorCode::AccessDenied, $description);
    }
}
