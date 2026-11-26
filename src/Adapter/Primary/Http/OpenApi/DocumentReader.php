<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Routing\PathTemplate;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\SchemaCompiler;
use Clavia\Adapter\Primary\Http\OpenApi\Schema\Type;
use Uri\Rfc3986\Uri;

/**
 * Reads a parsed OpenAPI 3.0 document into {@see Document}, checking it on the way.
 *
 * What it refuses, it refuses with the place (see {@see InvalidDocument}): structural
 * errors the specification rules out (a path parameter the template does not hold, a
 * reference to nothing, a security requirement naming an undeclared scheme or scope),
 * and every feature this validator does not implement — so a document either is
 * enforced as written, or does not load.
 */
final class DocumentReader
{
    private const array METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

    /** Headers OpenAPI 3.0 §4.7.12.1 says a `header` parameter must not describe. */
    private const array IGNORED_HEADERS = ['accept', 'content-type', 'authorization'];

    private readonly References $references;

    private readonly SchemaCompiler $schemas;

    /** @var array<string, list<string>|null> Declared scopes by security scheme; null for a scheme without scopes. */
    private array $schemes = [];

    /** @var array<string, string> operationId => where it is declared. */
    private array $operationIds = [];

    private function __construct(private readonly Node $root)
    {
        $this->references = new References($root);
        $this->schemas = new SchemaCompiler($this->references);
    }

    /**
     * @throws InvalidDocument
     */
    public static function read(Node $root): Document
    {
        return new self($root)->document();
    }

    private function document(): Document
    {
        $root = $this->root;
        $root->allowOnly(['openapi', 'info', 'servers', 'paths', 'components', 'security', 'tags', 'externalDocs']);

        $version = $root->member('openapi')->string();
        if (preg_match('/^3\.0\.\d+$/D', $version) !== 1) {
            throw $root->member('openapi')->invalid(sprintf("is '%s': only OpenAPI 3.0.x is supported", $version));
        }
        $root->member('info')->members();

        $this->readSecuritySchemes();
        $components = $root->optional('components');
        $components?->allowOnly([
            'schemas', 'responses', 'parameters', 'examples', 'requestBodies', 'headers', 'securitySchemes',
            'links', 'callbacks',
        ]);
        // Every component schema is compiled, used or not: a broken one is a broken document.
        foreach ($components?->optional('schemas')?->members() ?? [] as $schema) {
            $this->schemas->compile($schema);
        }

        $security = $this->security($root->optional('security')) ?? [];
        $operations = [];
        foreach ($root->member('paths')->members() as $pathItem) {
            foreach ($this->pathItem($pathItem->name, $pathItem, $security) as $operation) {
                $operations[] = $operation;
            }
        }
        $this->schemas->finish();

        return new Document($version, $operations, $this->basePaths());
    }

    /**
     * @param list<SecurityRequirement> $documentSecurity
     *
     * @return list<Operation>
     */
    private function pathItem(string $template, Node $item, array $documentSecurity): array
    {
        $path = PathTemplate::parse($template) ?? throw InvalidDocument::at(
            $item->pointer,
            'is not a path template (it must start with "/", and each {name} must be closed, named and used once)',
        );
        if (References::isReference($item)) {
            throw $item->invalid('is a Path Item reference, which is not supported');
        }
        $item->allowOnly([...self::METHODS, 'summary', 'description', 'parameters']);

        $shared = $this->parameters($item->optional('parameters'), $path);

        $operations = [];
        foreach (self::METHODS as $method) {
            $node = $item->optional($method);
            if ($node !== null) {
                $operations[] = $this->operation(strtoupper($method), $path, $node, $shared, $documentSecurity);
            }
        }

        return $operations;
    }

    /**
     * @param array<string, Parameter>  $shared
     * @param list<SecurityRequirement> $documentSecurity
     */
    private function operation(
        string $method,
        PathTemplate $path,
        Node $node,
        array $shared,
        array $documentSecurity,
    ): Operation {
        $node->allowOnly([
            'tags', 'summary', 'description', 'externalDocs', 'operationId', 'parameters', 'requestBody',
            'responses', 'callbacks', 'deprecated', 'security',
        ]);

        $operationId = $node->stringMember('operationId');
        if ($operationId !== null) {
            if (isset($this->operationIds[$operationId])) {
                throw $node->member('operationId')->invalid(sprintf(
                    "repeats '%s', already used at #%s",
                    $operationId,
                    $this->operationIds[$operationId],
                ));
            }
            $this->operationIds[$operationId] = $node->pointer;
        }

        $parameters = array_merge($shared, $this->parameters($node->optional('parameters'), $path));
        foreach ($path->parameterNames() as $name) {
            if (! isset($parameters['path:' . $name])) {
                throw $node->invalid(sprintf("does not describe the path parameter '%s'", $name));
            }
        }

        $requestBody = $node->optional('requestBody');

        return new Operation(
            $method,
            $path,
            $operationId,
            $parameters,
            $requestBody === null ? null : $this->requestBody($requestBody),
            $this->responses($node->member('responses')),
            $this->security($node->optional('security')) ?? $documentSecurity,
        );
    }

    /**
     * @return array<string, Parameter>
     */
    private function parameters(?Node $list, PathTemplate $path): array
    {
        $parameters = [];
        foreach ($list?->items() ?? [] as $item) {
            $parameter = $this->parameter($this->references->resolve($item), $path);
            if ($parameter === null) {
                continue;
            }
            if (isset($parameters[$parameter->key()])) {
                throw $item->invalid(sprintf(
                    "repeats the %s parameter '%s'",
                    $parameter->location->value,
                    $parameter->name,
                ));
            }
            $parameters[$parameter->key()] = $parameter;
        }

        return $parameters;
    }

    /**
     * @return Parameter|null Null for a header the specification says to ignore.
     */
    private function parameter(Node $node, PathTemplate $path): ?Parameter
    {
        if ($node->has('content')) {
            throw $node->member('content')->invalid('is not supported: describe the parameter with a schema');
        }
        $node->allowOnly([
            'name', 'in', 'description', 'required', 'deprecated', 'allowEmptyValue', 'style', 'explode',
            'allowReserved', 'schema', 'example', 'examples',
        ]);

        $name = $node->member('name')->string();
        $in = $node->member('in');
        $location = ParameterLocation::tryFrom($in->string())
            ?? throw $in->invalid('must be one of path, query, header, cookie');
        if ($location === ParameterLocation::Header) {
            $name = strtolower($name);
            if (in_array($name, self::IGNORED_HEADERS, true)) {
                return null;
            }
        }

        $required = $node->boolMember('required', false);
        if ($location === ParameterLocation::Path) {
            if (! $required) {
                throw $node->invalid('is a path parameter, which must be required: true');
            }
            if (! in_array($name, $path->parameterNames(), true)) {
                throw $node->invalid(sprintf("is the path parameter '%s', which the template does not hold", $name));
            }
        }

        $style = ParameterStyle::defaultFor($location);
        $styleName = $node->stringMember('style');
        if ($styleName !== null && $styleName !== $style->value) {
            throw $node->member('style')->invalid(sprintf(
                "is '%s', which is not supported for a %s parameter (only %s)",
                $styleName,
                $location->value,
                $style->value,
            ));
        }

        $schemaNode = $node->member('schema');
        $schema = $this->schemas->compile($schemaNode);
        $type = $this->references->resolve($schemaNode)->stringMember('type');
        if ($type === Type::Object->value) {
            throw $schemaNode->invalid('describes an object parameter, which is not supported');
        }

        return new Parameter(
            $name,
            $location,
            $required,
            $schema,
            $style,
            $node->boolMember('explode', $style === ParameterStyle::Form),
        );
    }

    private function requestBody(Node $node): RequestBody
    {
        $node = $this->references->resolve($node);
        $node->allowOnly(['description', 'content', 'required']);

        $content = $this->content($node->member('content'), request: true);
        if ($content->isEmpty()) {
            throw $node->member('content')->invalid('must describe at least one media type');
        }

        return new RequestBody($node->boolMember('required', false), $content);
    }

    private function responses(Node $node): Responses
    {
        $byStatus = [];
        foreach ($node->members() as $response) {
            $status = $response->name;
            if (preg_match('/^([1-5]\d\d|[1-5]XX|default)$/D', $status) !== 1) {
                throw $response->invalid('is not a status code, a range such as 4XX, or default');
            }
            $byStatus[$status] = $this->response($this->references->resolve($response));
        }
        if ($byStatus === []) {
            throw $node->invalid('must describe at least one response');
        }

        return new Responses($byStatus);
    }

    private function response(Node $node): Response
    {
        $node->allowOnly(['description', 'headers', 'content', 'links']);
        $node->member('description')->string();

        $headers = [];
        foreach ($node->optional('headers')?->members() ?? [] as $header) {
            $name = strtolower($header->name);
            // OpenAPI 3.0 §4.7.17: a Content-Type header definition is ignored.
            if ($name === 'content-type') {
                continue;
            }
            $header = $this->references->resolve($header);
            $header->allowOnly([
                'description', 'required', 'deprecated', 'style', 'explode', 'schema', 'example', 'examples',
            ]);
            if (($header->stringMember('style') ?? 'simple') !== 'simple') {
                throw $header->member('style')->invalid('must be simple for a header');
            }
            $headers[$name] = new Header(
                $name,
                $header->boolMember('required', false),
                $this->schemas->compile($header->member('schema')),
            );
        }

        $content = $node->optional('content');

        return new Response($headers, $content === null ? new Content([]) : $this->content($content));
    }

    /** @param bool $request A request body's content, where a form may be described. */
    private function content(Node $node, bool $request = false): Content
    {
        $entries = [];
        foreach ($node->members() as $mediaTypeNode) {
            $range = $mediaTypeNode->name;
            $mediaType = MediaType::parse($range) ?? throw $mediaTypeNode->invalid('is not a media type');
            if ($request && $mediaType->isForm()) {
                // A form is named strings (WHATWG URL §5.1), so a schema can hold it only when every
                // value it describes is a string: anything else could never match, or would need a
                // coercion this validator refuses to guess (`"02"` is not an integer).
                $mediaTypeNode->allowOnly(['schema', 'example', 'examples']);
                $schema = $mediaTypeNode->optional('schema')
                    ?? throw $mediaTypeNode->invalid('must have a schema: an object of string properties');
                $this->formSchema($schema);
                $entries[$range] = [$mediaType, $this->schemas->compile($schema)];
                continue;
            }
            if (! $mediaType->isJson()) {
                // Any other body is opaque bytes, and said so: `{type: string, format: binary}` is
                // the one schema this validator can enforce on it (it accepts any bytes). What the
                // bytes mean (NDJSON lines, for one) is the operation's to check, after.
                $mediaTypeNode->allowOnly(['schema', 'example', 'examples']);
                $schema = $mediaTypeNode->optional('schema');
                $names = $schema?->names() ?? [];
                sort($names);
                $opaque = $schema !== null
                    && $names === ['format', 'type']
                    && $schema->stringMember('type') === 'string'
                    && $schema->stringMember('format') === 'binary';
                if (! $opaque) {
                    throw $mediaTypeNode->invalid(
                        'is not a JSON media type: its schema must be {type: string, format: binary}, '
                        . 'opaque bytes',
                    );
                }
                $entries[$range] = [$mediaType, null];
                continue;
            }
            $mediaTypeNode->allowOnly(['schema', 'example', 'examples']);
            $schema = $mediaTypeNode->optional('schema');
            $entries[$range] = [$mediaType, $schema === null ? null : $this->schemas->compile($schema)];
        }

        return new Content($entries);
    }

    /**
     * Refuses a form's schema this validator cannot enforce: it must be an `object` whose properties
     * are strings, or `allOf`, `anyOf` or `oneOf` of such objects (one schema per `grant_type`, sharing
     * the client's fields). A property is `type: string`, never nullable, with any string keyword.
     */
    private function formSchema(Node $node): void
    {
        $node = $this->references->resolve($node);
        $combined = false;
        foreach (['allOf', 'anyOf', 'oneOf'] as $keyword) {
            foreach ($node->optional($keyword)?->items() ?? [] as $member) {
                $this->formSchema($member);
                $combined = true;
            }
        }
        if ($node->optional('not') !== null) {
            throw $node->member('not')->invalid('cannot be enforced on a form');
        }
        $type = $node->stringMember('type');
        if ($type === null && $combined && $node->optional('properties') === null) {
            return;
        }
        if ($type !== Type::Object->value) {
            throw $node->invalid('describes a form: it must be an object of string properties');
        }
        foreach ($node->optional('properties')?->members() ?? [] as $property) {
            $this->formValue($property);
        }
        $additional = $node->optional('additionalProperties');
        if ($additional !== null && ! is_bool($additional->value)) {
            $this->formValue($additional);
        }
    }

    private function formValue(Node $node): void
    {
        $resolved = $this->references->resolve($node);
        if ($resolved->stringMember('type') !== Type::String->value || $resolved->boolMember('nullable', false)) {
            throw $node->invalid('is a form value: it must be {type: string}, not nullable');
        }
    }

    /**
     * @return list<SecurityRequirement>|null Null when the node is absent: inherit.
     */
    private function security(?Node $node): ?array
    {
        if ($node === null) {
            return null;
        }

        $requirements = [];
        foreach ($node->items() as $item) {
            $scopes = [];
            foreach ($item->members() as $list) {
                $scheme = $list->name;
                if (! array_key_exists($scheme, $this->schemes)) {
                    throw $list->invalid(sprintf("names the security scheme '%s', which is not declared", $scheme));
                }
                $names = array_map(static fn (Node $scope): string => $scope->string(), $list->items());
                $declared = $this->schemes[$scheme];
                foreach ($names as $index => $name) {
                    if ($declared !== null && ! in_array($name, $declared, true)) {
                        throw $list->items()[$index]->invalid(sprintf("is not a scope '%s' declares", $scheme));
                    }
                }
                $scopes[$scheme] = $names;
            }
            $requirements[] = new SecurityRequirement($scopes);
        }

        return $requirements;
    }

    private function readSecuritySchemes(): void
    {
        $declared = $this->root->optional('components')?->optional('securitySchemes')?->members() ?? [];
        foreach ($declared as $node) {
            $name = $node->name;
            $node = $this->references->resolve($node);
            $type = $node->member('type')->string();
            if ($type !== 'oauth2' && $type !== 'openIdConnect') {
                // Other schemes take no scopes (§4.7.30): a requirement must list none.
                $this->schemes[$name] = [];
                continue;
            }
            if ($type === 'openIdConnect') {
                $this->schemes[$name] = null;
                continue;
            }

            $scopes = [];
            foreach ($node->member('flows')->members() as $flow) {
                foreach ($flow->member('scopes')->names() as $scope) {
                    $scopes[] = $scope;
                }
            }
            $this->schemes[$name] = array_values(array_unique($scopes));
        }
    }

    /**
     * The path prefix of each server (`servers[].url`): `/` when there are none.
     *
     * @return list<string> Without a trailing `/`.
     */
    private function basePaths(): array
    {
        $servers = $this->root->optional('servers')?->items() ?? [];
        if ($servers === []) {
            return [''];
        }

        $paths = [];
        foreach ($servers as $server) {
            $server->allowOnly(['url', 'description']);
            $url = $server->member('url')->string();
            if (str_contains($url, '{')) {
                throw $server->member('url')->invalid('uses server variables, which are not supported');
            }
            $parsed = Uri::parse($url) ?? throw $server->member('url')->invalid('is not a URL');
            $paths[] = rtrim($parsed->getPath(), '/');
        }

        return array_values(array_unique($paths));
    }
}
