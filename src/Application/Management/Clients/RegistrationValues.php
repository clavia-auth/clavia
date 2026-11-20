<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\ResponseType;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * The registration vocabulary of the Management API, read into the domain's types.
 */
final class RegistrationValues
{
    private function __construct()
    {
    }

    /**
     * @throws InvalidValue
     */
    public static function authMethod(string $value): ClientAuthMethod
    {
        return ClientAuthMethod::tryFrom($value)
            ?? throw new InvalidValue(sprintf("Unsupported token endpoint authentication method '%s'.", $value));
    }

    /**
     * @param list<string> $values
     *
     * @return list<Url>
     *
     * @throws InvalidValue
     */
    public static function redirectUris(array $values): array
    {
        return array_map(Url::fromString(...), $values);
    }

    /**
     * @param list<string> $values
     *
     * @return list<GrantType>
     *
     * @throws InvalidValue
     */
    public static function grantTypes(array $values): array
    {
        return array_map(
            static fn (string $value): GrantType => GrantType::tryFrom($value)
                ?? throw new InvalidValue(sprintf("Unsupported grant type '%s'.", $value)),
            $values,
        );
    }

    /**
     * @param list<string> $values
     *
     * @return list<ResponseType>
     *
     * @throws InvalidValue
     */
    public static function responseTypes(array $values): array
    {
        return array_map(
            static fn (string $value): ResponseType => ResponseType::tryFrom($value)
                ?? throw new InvalidValue(sprintf("Unsupported response type '%s'.", $value)),
            $values,
        );
    }
}
