<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Acceptance;

use ClaviaTest\Support\AcceptanceTestCase;
use ClaviaTest\Support\AuthorizationServerContract;
use Fig\Http\Message\StatusCodeInterface;
use stdClass;
use Symfony\Component\Yaml\Yaml;

/**
 * What discovery says this server supports, and what its document describes, are the same (#93):
 * discovery reads its grant types and client authentication methods from the code, so the document
 * cannot list one the server does not have, or miss one it does.
 */
final class DiscoveryAgreesWithDocumentTest extends AcceptanceTestCase
{
    public function testGrantsMethodsAndAlgorithmsAreTheDocumentsEnums(): void
    {
        $this->boot(['CLAVIA_CLIENT_REGISTRATION' => 'token']);
        $response = $this->get('/.well-known/openid-configuration');
        self::assertSame(StatusCodeInterface::STATUS_OK, $response->getStatusCode());
        /** @var array<string, mixed> $discovery */
        $discovery = json_decode((string) $response->getBody(), true, flags: JSON_THROW_ON_ERROR);
        $metadata = self::at(self::schema('ProviderMetadata'), 'properties');

        foreach (
            [
                'grant_types_supported',
                'code_challenge_methods_supported',
                'dpop_signing_alg_values_supported',
                'response_types_supported',
            ] as $member
        ) {
            self::assertEqualsCanonicalizing(
                self::enum(self::resolve(self::at($metadata, $member, 'items'))),
                $discovery[$member],
                $member,
            );
        }
        // Introspection answers only a client with a secret (RFC 7662 §2.1 leaves it to the server).
        $methods = [
            'token' => 'ClientAuthMethod',
            'introspection' => 'SecretClientAuthMethod',
            'revocation' => 'ClientAuthMethod',
        ];
        foreach ($methods as $endpoint => $schema) {
            $member = $endpoint . '_endpoint_auth_methods_supported';
            self::assertEqualsCanonicalizing(self::enum(self::schema($schema)), $discovery[$member], $member);
            self::assertSame(
                '#/components/schemas/' . $schema,
                self::at($metadata, $member, 'items')->{'$ref'} ?? null,
                $member . ' is described by ' . $schema,
            );
        }
    }

    public function testTheTokenRequestHasOneSchemaPerGrant(): void
    {
        $body = self::at(self::raw(), 'paths', '/oauth2/token', 'post', 'requestBody', 'content');
        $grants = [];
        foreach (self::list(self::at($body, 'application/x-www-form-urlencoded', 'schema'), 'oneOf') as $grant) {
            foreach (self::list(self::resolve($grant), 'allOf') as $part) {
                $part = self::resolve($part);
                $hasGrantType = property_exists($part, 'properties')
                    && property_exists(self::at($part, 'properties'), 'grant_type');
                if ($hasGrantType) {
                    $grants = [...$grants, ...self::enum(self::at($part, 'properties', 'grant_type'))];
                }
            }
        }

        $supported = self::at(self::schema('ProviderMetadata'), 'properties', 'grant_types_supported', 'items');
        self::assertEqualsCanonicalizing(self::enum($supported), $grants);
    }

    /** @return list<string> */
    private static function enum(stdClass $schema): array
    {
        $enum = $schema->enum ?? null;
        self::assertIsArray($enum);
        $values = [];
        /** @var mixed $value */
        foreach ($enum as $value) {
            self::assertIsString($value);
            $values[] = $value;
        }

        return $values;
    }

    /** The object at `$path` under `$node`, each step an object. */
    private static function at(stdClass $node, string ...$path): stdClass
    {
        foreach ($path as $name) {
            $next = $node->{$name} ?? null;
            self::assertInstanceOf(stdClass::class, $next, $name);
            $node = $next;
        }

        return $node;
    }

    /** @return list<stdClass> */
    private static function list(stdClass $node, string $name): array
    {
        $items = $node->{$name} ?? null;
        self::assertIsArray($items, $name);
        $objects = [];
        /** @var mixed $item */
        foreach ($items as $item) {
            self::assertInstanceOf(stdClass::class, $item);
            $objects[] = $item;
        }

        return $objects;
    }

    private static function schema(string $name): stdClass
    {
        return self::resolve(self::at(self::raw(), 'components', 'schemas', $name));
    }

    private static function resolve(stdClass $node): stdClass
    {
        $ref = $node->{'$ref'} ?? null;
        if ($ref === null) {
            return $node;
        }
        self::assertIsString($ref);

        return self::schema(substr($ref, strlen('#/components/schemas/')));
    }

    private static function raw(): stdClass
    {
        $raw = Yaml::parseFile(AuthorizationServerContract::PATH, Yaml::PARSE_OBJECT_FOR_MAP);
        self::assertInstanceOf(stdClass::class, $raw);

        return $raw;
    }
}
