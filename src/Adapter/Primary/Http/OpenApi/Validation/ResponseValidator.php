<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use Clavia\Adapter\Primary\Http\OpenApi\Content;
use Clavia\Adapter\Primary\Http\OpenApi\MediaType;
use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Direction;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaValidator;
use JsonException;
use Psr\Http\Message\ResponseInterface;

/**
 * Checks a PSR-7 response against what its operation describes: the status is listed
 * (exactly, as a range, or as `default`), every required header is present and every
 * described header valid, and the body is absent where none is described, and
 * otherwise JSON of a described media type, valid against its schema.
 *
 * For tests and for development guards: a mismatch is a defect of the server, so it is
 * reported as {@see ResponseDoesNotMatch} with every violation found.
 */
final class ResponseValidator
{
    private function __construct()
    {
    }

    /**
     * @throws ResponseDoesNotMatch
     */
    public static function validate(Operation $operation, ResponseInterface $response): void
    {
        $status = $response->getStatusCode();
        $described = $operation->responses->for($status);
        if ($described === null) {
            throw new ResponseDoesNotMatch($operation, [
                new Violation(
                    Location::Status,
                    null,
                    '',
                    sprintf('%d is not a status this operation describes.', $status),
                ),
            ]);
        }

        $violations = [];
        foreach ($described->headers as $header) {
            if (! $response->hasHeader($header->name)) {
                if ($header->required) {
                    $violations[] = Violation::inParameter(Location::Header, $header->name, 'Is required.');
                }
                continue;
            }
            /** @var mixed $value */
            $value = ParameterDecoder::decode($header->schema, [$response->getHeaderLine($header->name)], false);
            $violations = [...$violations, ...Violation::fromSchema(
                Location::Header,
                $header->name,
                SchemaValidator::validate($value, $header->schema, Direction::Response),
            )];
        }

        $raw = (string) $response->getBody();
        if ($described->content->isEmpty()) {
            if ($raw !== '') {
                $violations[] = Violation::inBody('', 'Is present where the operation describes no body.');
            }
        } else {
            $violations = [...$violations, ...self::body($described->content, $response, $raw)];
        }

        if ($violations !== []) {
            throw new ResponseDoesNotMatch($operation, $violations);
        }
    }

    /**
     * @return list<Violation>
     */
    private static function body(Content $content, ResponseInterface $response, string $raw): array
    {
        $mediaType = MediaType::parse($response->getHeaderLine('Content-Type'));
        $entry = $mediaType === null ? null : $content->for($mediaType);
        if ($entry === null) {
            return [Violation::inParameter(Location::Header, 'content-type', sprintf(
                'Must be %s.',
                implode(' or ', $content->mediaTypes()),
            ))];
        }

        try {
            /** @var mixed $body */
            $body = json_decode($raw, false, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (JsonException) {
            return [Violation::inBody('', 'Is not valid JSON.')];
        }

        $violations = $entry[1] === null ? [] : SchemaValidator::validate($body, $entry[1], Direction::Response);

        return Violation::fromSchema(Location::Body, null, $violations);
    }
}
