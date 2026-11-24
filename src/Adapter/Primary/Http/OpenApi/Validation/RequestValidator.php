<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi\Validation;

use Clavia\Adapter\Primary\Http\OpenApi\Document;
use Clavia\Adapter\Primary\Http\OpenApi\MediaType;
use Clavia\Adapter\Primary\Http\OpenApi\Operation;
use Clavia\Adapter\Primary\Http\OpenApi\Parameter;
use Clavia\Adapter\Primary\Http\OpenApi\ParameterLocation;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Direction;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaValidator;
use JsonException;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Checks a PSR-7 request against the operation the document describes for it, and
 * hands back its decoded parts ({@see ValidatedRequest}).
 *
 * In order, each step reporting everything it finds:
 *
 *  1. the operation — none: {@see OperationNotFound};
 *  2. what can be read at all — percent-encoding, repeated single values, JSON syntax:
 *     {@see MalformedRequest};
 *  3. the body's media type: {@see UnsupportedMediaType};
 *  4. everything the document says — required parameters present, no query parameter
 *     it does not describe, every value and the body valid against its schema:
 *     {@see RequestDoesNotMatch}.
 *
 * Strict where the specification leaves room: a query parameter the operation does not
 * describe is refused like a body member the schema does not allow, and a body sent to
 * an operation that takes none is refused rather than ignored.
 */
final readonly class RequestValidator
{
    public function __construct(private Document $document)
    {
    }

    /**
     * @throws OperationNotFound
     * @throws RequestRejected
     */
    public function validate(ServerRequestInterface $request): ValidatedRequest
    {
        $path = $request->getUri()->getPath();
        $match = $this->document->match($request->getMethod(), $path)
            ?? throw new OperationNotFound($request->getMethod(), $path, $this->document->knowsPath($path));
        $operation = $match->operation;

        $malformed = [];
        /** @var array<string, array{Parameter, list<string>}> $values */
        $values = [];

        foreach ($operation->parametersIn(ParameterLocation::Path) as $parameter) {
            $raw = rawurldecode($match->pathValues[$parameter->name] ?? '');
            if (! mb_check_encoding($raw, 'UTF-8')) {
                $malformed[] = Violation::inParameter(Location::Path, $parameter->name, 'Is not valid UTF-8.');
                continue;
            }
            $values[$parameter->key()] = [$parameter, [$raw]];
        }

        $query = QueryString::parse($request->getUri()->getQuery());
        if ($query === null) {
            $malformed[] = new Violation(Location::Query, null, '', 'Is not valid UTF-8.');
        }
        $unknown = [];
        if ($query !== null) {
            $described = [];
            foreach ($operation->parametersIn(ParameterLocation::Query) as $parameter) {
                $described[] = $parameter->name;
                $sent = $query->values($parameter->name);
                if ($sent !== []) {
                    $values[$parameter->key()] = [$parameter, $sent];
                }
            }
            foreach ($query->names() as $name) {
                if (! in_array($name, $described, true)) {
                    $unknown[] = Violation::inParameter(
                        Location::Query,
                        $name,
                        'Is not a parameter of this operation.',
                    );
                }
            }
        }

        foreach ($operation->parametersIn(ParameterLocation::Header) as $parameter) {
            if ($request->hasHeader($parameter->name)) {
                // Several header fields of one name are one comma-separated list (RFC 9110 §5.3).
                $values[$parameter->key()] = [$parameter, [$request->getHeaderLine($parameter->name)]];
            }
        }

        $cookies = self::cookies($request);
        foreach ($operation->parametersIn(ParameterLocation::Cookie) as $parameter) {
            if (isset($cookies['c:' . $parameter->name])) {
                $values[$parameter->key()] = [$parameter, $cookies['c:' . $parameter->name]];
            }
        }

        /** @var array<string, mixed> $decoded */
        $decoded = [];
        foreach ($values as $key => [$parameter, $sent]) {
            /** @var mixed $value */
            $value = ParameterDecoder::decode($parameter->schema, $sent, $parameter->explode);
            if ($value === null) {
                $malformed[] = Violation::inParameter(
                    self::location($parameter),
                    $parameter->name,
                    'Is sent more than once.',
                );
                continue;
            }
            /** @psalm-suppress MixedAssignment A JSON value: its schema says what it is. */
            $decoded[$key] = $value;
        }

        /** @var mixed $body */
        [$hasBody, $body, $bodyViolations] = $this->body($operation, $request, $malformed);

        if ($malformed !== []) {
            throw new MalformedRequest('The request cannot be read.', $malformed);
        }

        $violations = $unknown;
        foreach ($operation->parameters as $parameter) {
            if (! array_key_exists($parameter->key(), $decoded)) {
                if ($parameter->required) {
                    $violations[] = Violation::inParameter(
                        self::location($parameter),
                        $parameter->name,
                        'Is required.',
                    );
                }
                continue;
            }
            $violations = [...$violations, ...Violation::fromSchema(
                self::location($parameter),
                $parameter->name,
                SchemaValidator::validate($decoded[$parameter->key()], $parameter->schema, Direction::Request),
            )];
        }
        $violations = [...$violations, ...$bodyViolations];

        if ($violations !== []) {
            throw new RequestDoesNotMatch(
                sprintf('The request does not match the operation %s.', (string) $operation),
                $violations,
            );
        }

        return new ValidatedRequest($operation, $decoded, $hasBody, $body);
    }

    /**
     * The body, decoded, with what is wrong with it. Unreadable JSON goes to
     * `$malformed`; the wrong media type is thrown at once.
     *
     * @param list<Violation> $malformed
     *
     * @return array{bool, mixed, list<Violation>}
     *
     * @throws UnsupportedMediaType
     */
    private function body(Operation $operation, ServerRequestInterface $request, array &$malformed): array
    {
        $raw = (string) $request->getBody();
        $requestBody = $operation->requestBody;

        if ($raw === '') {
            return $requestBody?->required === true
                ? [false, null, [Violation::inBody('', 'A body is required.')]]
                : [false, null, []];
        }
        if ($requestBody === null) {
            return [false, null, [Violation::inBody('', 'This operation takes no body.')]];
        }

        $contentType = $request->getHeaderLine('Content-Type');
        $mediaType = MediaType::parse($contentType);
        $entry = $mediaType === null ? null : $requestBody->content->for($mediaType);
        if ($mediaType === null || $entry === null) {
            throw new UnsupportedMediaType(sprintf(
                'The body must be %s.',
                implode(' or ', $requestBody->content->mediaTypes()),
            ));
        }
        if ($mediaType->charset !== null && $mediaType->charset !== 'utf-8') {
            throw new UnsupportedMediaType('A JSON body is UTF-8 (RFC 8259 §8.1).');
        }
        if (! $entry[0]->isJson()) {
            // Opaque bytes ({type: string, format: binary}): the operation reads them itself.
            return [true, $raw, []];
        }

        try {
            /** @var mixed $body */
            $body = json_decode($raw, false, 512, JSON_THROW_ON_ERROR | JSON_BIGINT_AS_STRING);
        } catch (JsonException) {
            $malformed[] = Violation::inBody('', 'Is not valid JSON.');

            return [true, null, []];
        }

        $schema = $entry[1];
        $violations = $schema === null ? [] : SchemaValidator::validate($body, $schema, Direction::Request);

        return [true, $body, Violation::fromSchema(Location::Body, null, $violations)];
    }

    /**
     * The `Cookie` header's pairs (RFC 6265 §5.4), every value of a name kept.
     *
     * @return array<string, list<string>> Keyed `c:<name>`, for lookup only.
     */
    private static function cookies(ServerRequestInterface $request): array
    {
        $cookies = [];
        foreach ($request->getHeader('Cookie') as $line) {
            foreach (explode(';', $line) as $pair) {
                [$name, $value] = array_pad(explode('=', trim($pair), 2), 2, '');
                if ($name !== '') {
                    $cookies['c:' . $name][] = $value;
                }
            }
        }

        return $cookies;
    }

    private static function location(Parameter $parameter): Location
    {
        return Location::from($parameter->location->value);
    }
}
