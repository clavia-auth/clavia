<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OpenApi;

use Clavia\Adapter\Primary\Http\OpenApi\Routing\RouteMatch;
use Clavia\Adapter\Primary\Http\OpenApi\Routing\Router;
use JsonException;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * An OpenAPI 3.0 document, loaded and checked: its operations, and the router that
 * finds the one a request is.
 *
 * Loading does all the work that can be done once — references followed, schemas
 * compiled, every unsupported feature refused ({@see DocumentReader}) — so validating
 * a request does none of it.
 */
final readonly class Document
{
    private Router $router;

    /**
     * @param list<Operation> $operations
     * @param list<string>    $basePaths
     */
    public function __construct(
        public string $version,
        private array $operations,
        array $basePaths,
    ) {
        $this->router = new Router($operations, $basePaths);
    }

    /**
     * @throws InvalidDocument When the file cannot be read or parsed, or the document is not
     *                         one this validator can enforce.
     */
    public static function fromYamlFile(string $path): self
    {
        $yaml = is_file($path) ? file_get_contents($path) : false;
        if ($yaml === false) {
            throw new InvalidDocument(sprintf("The OpenAPI document '%s' cannot be read.", $path));
        }

        return self::fromYaml($yaml);
    }

    /**
     * @throws InvalidDocument
     */
    public static function fromYaml(string $yaml): self
    {
        try {
            /** @var mixed $parsed */
            $parsed = Yaml::parse(
                $yaml,
                Yaml::PARSE_OBJECT_FOR_MAP | Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE,
            );
        } catch (ParseException $failure) {
            throw new InvalidDocument('The OpenAPI document is not valid YAML: ' . $failure->getMessage(), 0, $failure);
        }

        return DocumentReader::read(Node::root($parsed));
    }

    /**
     * @throws InvalidDocument
     */
    public static function fromJson(string $json): self
    {
        try {
            /** @var mixed $parsed */
            $parsed = json_decode($json, false, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $failure) {
            throw new InvalidDocument('The OpenAPI document is not valid JSON: ' . $failure->getMessage(), 0, $failure);
        }

        return DocumentReader::read(Node::root($parsed));
    }

    /**
     * @return list<Operation>
     */
    public function operations(): array
    {
        return $this->operations;
    }

    /** The operation `$method` on `$path` is, if the document describes one. */
    public function match(string $method, string $path): ?RouteMatch
    {
        return $this->router->match($method, $path);
    }

    /** Whether the document describes `$path` for some method. */
    public function knowsPath(string $path): bool
    {
        return $this->router->knowsPath($path);
    }
}
