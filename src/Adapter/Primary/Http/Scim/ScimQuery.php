<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\OAuth2\RequestParameters;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * What a SCIM request's query says (RFC 7644 §3.4.2): `filter`, `startIndex`, `count`, and
 * `excludedAttributes`. A parameter is sent once.
 */
final readonly class ScimQuery
{
    private function __construct(private RequestParameters $parameters)
    {
    }

    /**
     * @throws ScimRequestRejected When a parameter is sent twice.
     */
    public static function of(ServerRequestInterface $request): self
    {
        $parameters = RequestParameterReader::query($request);
        if ($parameters->repeated() !== []) {
            throw new ScimRequestRejected(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                'A query parameter is sent once.',
                'invalidValue',
            );
        }

        return new self($parameters);
    }

    public function filter(): ?string
    {
        return $this->parameters->get('filter');
    }

    /**
     * @throws ScimRequestRejected When it is not an integer.
     */
    public function integer(string $name, int $default): int
    {
        $value = $this->parameters->get($name);
        if ($value === null) {
            return $default;
        }
        if (preg_match('/^-?\d{1,9}$/D', $value) !== 1) {
            throw new ScimRequestRejected(
                StatusCodeInterface::STATUS_BAD_REQUEST,
                sprintf("'%s' is an integer.", $name),
                'invalidValue',
            );
        }

        return (int) $value;
    }

    /** Whether `excludedAttributes` names this attribute (a comma-separated list, any case). */
    public function excludes(string $attribute): bool
    {
        $excluded = array_map(
            static fn (string $name): string => strtolower(trim($name)),
            explode(',', $this->parameters->get('excludedAttributes') ?? ''),
        );

        return in_array(strtolower($attribute), $excluded, true);
    }
}
