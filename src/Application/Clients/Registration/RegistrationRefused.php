<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use RuntimeException;

/**
 * A registration refused for what it asked (RFC 7591 §3.2.2): a `400` with `error` and
 * `error_description`. The description names the field at fault, never its value.
 */
final class RegistrationRefused extends RuntimeException
{
    private function __construct(public readonly RegistrationErrorCode $error, string $description)
    {
        parent::__construct($description);
    }

    public static function redirectUri(string $description): self
    {
        return new self(RegistrationErrorCode::InvalidRedirectUri, $description);
    }

    public static function metadata(string $description): self
    {
        return new self(RegistrationErrorCode::InvalidClientMetadata, $description);
    }

    public static function softwareStatement(): self
    {
        return new self(
            RegistrationErrorCode::InvalidSoftwareStatement,
            'This server does not accept software statements.',
        );
    }
}
