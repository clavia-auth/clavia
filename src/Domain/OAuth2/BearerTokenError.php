<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Authentication\AuthenticationRequirement;
use Clavia\Domain\Shared\ScopeSet;
use DomainException;

/**
 * A protected resource refusing the bearer token it was given (RFC 6750 §3).
 *
 * The primary adapter turns it into the status and the `WWW-Authenticate` challenge
 * the RFC prescribes; nothing here knows about HTTP.
 */
final class BearerTokenError extends DomainException
{
    private function __construct(
        public readonly BearerErrorCode $error,
        public readonly string $description,
        public readonly ?ScopeSet $requiredScope,
        public readonly ?AuthenticationRequirement $requiredAuthentication = null,
    ) {
        parent::__construct($error->value . ': ' . $description);
    }

    public static function invalidRequest(string $description): self
    {
        return new self(BearerErrorCode::InvalidRequest, $description, null);
    }

    public static function invalidToken(string $description): self
    {
        return new self(BearerErrorCode::InvalidToken, $description, null);
    }

    /**
     * @param ScopeSet $required The scope the resource needs, stated in the challenge so the client
     *                           knows what to ask for.
     */
    public static function insufficientScope(ScopeSet $required, string $description): self
    {
        return new self(BearerErrorCode::InsufficientScope, $description, $required);
    }

    /**
     * @param AuthenticationRequirement $required What the sign-in must meet, stated in the challenge as
     *                                            `acr_values` (RFC 9470 §3) so the client knows what to ask.
     */
    public static function insufficientUserAuthentication(
        AuthenticationRequirement $required,
        string $description,
    ): self {
        return new self(BearerErrorCode::InsufficientUserAuthentication, $description, null, $required);
    }
}
