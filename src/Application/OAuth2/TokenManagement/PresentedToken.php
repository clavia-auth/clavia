<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\TokenManagement;

use Clavia\Application\OAuth2\RequestParameters;
use Clavia\Domain\OAuth2\OAuth2Error;

/**
 * The token a client asks about or gives back, and the hint it gave of its kind.
 */
final readonly class PresentedToken
{
    /**
     * @param non-empty-string $value
     */
    private function __construct(
        #[\SensitiveParameter] public string $value,
        public ?TokenTypeHint $hint,
    ) {
    }

    /**
     * Read `token` and `token_type_hint` from a request already authenticated.
     *
     * @throws OAuth2Error `invalid_request` for a missing token or a repeated parameter (RFC 6749 §3.2),
     *                     `unsupported_token_type` for a hint naming a kind this server does not
     *                     keep (RFC 7009 §2.2.1).
     */
    public static function from(RequestParameters $parameters): self
    {
        $repeated = $parameters->repeated();
        if ($repeated !== []) {
            throw OAuth2Error::invalidRequest(sprintf("Repeated '%s' parameter.", $repeated[0]));
        }

        $value = $parameters->get('token');
        if ($value === null || $value === '') {
            throw OAuth2Error::invalidRequest("Missing 'token' parameter.");
        }

        $hint = $parameters->get('token_type_hint');
        $type = $hint === null ? null : TokenTypeHint::tryFrom($hint);
        if ($hint !== null && $type === null) {
            throw OAuth2Error::unsupportedTokenType(
                "'token_type_hint' is 'access_token' or 'refresh_token' here.",
            );
        }

        return new self($value, $type);
    }
}
