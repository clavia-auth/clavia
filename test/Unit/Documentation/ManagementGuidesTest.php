<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Documentation;

use Clavia\Application\Management\ManagementPermission;
use Clavia\Bootstrap\ConfigProvider;
use Clavia\Configuration\Settings;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use ReflectionClass;
use Symfony\Component\Yaml\Yaml;

/**
 * The Management API guides (docs/guides, #98) say only what is so: every operation, scope, console
 * command and setting they name exists, they are all listed where a reader finds them, and they
 * name no real host. What they say beyond names was checked against a running server when written;
 * this keeps the names from drifting.
 */
final class ManagementGuidesTest extends TestCase
{
    private const string GUIDES = __DIR__ . '/../../../docs/guides';
    private const string DOCUMENT = __DIR__ . '/../../../docs/openapi/management-api.yaml';
    private const string AUTHORIZATION_SERVER = __DIR__ . '/../../../docs/openapi/authorization-server.yaml';
    private const string PAGE = __DIR__ . '/../../../docs/site/guide.html';

    /** Hosts a guide may name: the reader's own (example.com), a partner's, and the specifications. */
    private const string ALLOWED_HOSTS = '/^(?:(?:auth|management)\.example\.com|reports\.acme\.example|'
        . 'www\.rfc-editor\.org|github\.com|schemas\.openid\.net)$/D';

    public function testTheIndexListsEveryGuideInItsOrder(): void
    {
        $listed = array_keys(self::listed());
        $paths = glob(self::GUIDES . '/*.md');
        self::assertIsArray($paths);
        $files = array_values(array_diff(array_map(
            static fn (string $path): string => basename($path, '.md'),
            $paths,
        ), ['README']));
        sort($files);
        $sorted = $listed;
        sort($sorted);

        self::assertSame($files, $sorted, 'README.md lists every guide, and only those.');
        self::assertNotEmpty($listed);
    }

    public function testTheReferenceLinksEveryGuideUnderTheSameTitle(): void
    {
        $document = Yaml::parseFile(self::DOCUMENT);
        self::assertIsArray($document);
        $description = (string) ($document['info']['description'] ?? '');
        preg_match_all('#\[([^\]]+)\]\(guides/([a-z0-9-]+)\.html\)#', $description, $links, PREG_SET_ORDER);
        $linked = [];
        foreach ($links as $link) {
            $linked[$link[2]] = $link[1];
        }

        self::assertSame(self::listed(), $linked, 'info.description links every guide, in order.');
    }

    /** An operation a guide names is in the document of its host: `/api/v1` or the authorization server's. */
    #[DataProvider('guides')]
    public function testEachOperationNamedExists(string $guide): void
    {
        $operation = '#\b(GET|POST|PUT|PATCH|DELETE) '
            . '(/(?:api/v1|oauth2|oidc|\.well-known)/[A-Za-z0-9_/{}.-]*[A-Za-z0-9_}])#';
        preg_match_all($operation, self::text($guide), $named, PREG_SET_ORDER);

        foreach ($named as [, $method, $path]) {
            $paths = self::paths(str_starts_with($path, '/api/v1/') ? self::DOCUMENT : self::AUTHORIZATION_SERVER);
            self::assertArrayHasKey(
                strtolower($method),
                $paths[$path] ?? [],
                sprintf('%s.md names %s %s, which the document does not have.', $guide, $method, $path),
            );
        }
    }

    /**
     * A link into the authorization server's reference lands on a tag it has, or an operation of that
     * tag: `#tag/<tag>` or `#tag/<tag>/<METHOD>/<path>`, as Scalar names them.
     */
    #[DataProvider('guides')]
    public function testLinksIntoTheAuthorizationServersReferenceLandOnSomething(string $guide): void
    {
        preg_match_all('#\(\.\./openapi/authorization-server\.yaml(?:\#([^)]*))?\)#', self::text($guide), $links);
        $document = Yaml::parseFile(self::AUTHORIZATION_SERVER);
        self::assertIsArray($document);
        /** @var list<array{name: string}> $declared */
        $declared = $document['tags'];
        $tags = array_column($declared, 'name');

        foreach ($links[1] as $fragment) {
            if ($fragment === '') {
                continue;
            }
            self::assertSame(1, preg_match('#^tag/([a-z-]+)(?:/([A-Z]+)(/.+))?$#D', $fragment, $target), $fragment);
            self::assertContains($target[1], $tags, $guide . '.md links a tag the reference lacks.');
            if (isset($target[2])) {
                $operation = self::paths(self::AUTHORIZATION_SERVER)[$target[3]][strtolower($target[2])] ?? null;
                self::assertIsArray($operation, $guide . '.md links ' . $fragment . ', which is no operation.');
                self::assertSame([$target[1]], $operation['tags'] ?? null, $fragment . ' is under another tag.');
            }
        }
    }

    #[DataProvider('guides')]
    public function testEachScopeNamedExists(string $guide): void
    {
        $scopes = array_map(static fn (ManagementPermission $p): string => $p->value, ManagementPermission::cases());
        preg_match_all('/\b(?:read|create|update|delete):[a-z_]+\b/', self::text($guide), $named);

        foreach (array_unique($named[0]) as $scope) {
            self::assertContains($scope, $scopes, sprintf('%s.md names %s.', $guide, $scope));
        }
    }

    #[DataProvider('guides')]
    public function testEachConsoleCommandNamedExists(string $guide): void
    {
        preg_match_all('/\$CLAVIA ([a-z0-9:-]+)/', self::text($guide), $named);

        foreach (array_unique($named[1]) as $command) {
            self::assertArrayHasKey(
                $command,
                ConfigProvider::CONSOLE_COMMANDS,
                sprintf('%s.md names the command %s.', $guide, $command),
            );
        }
    }

    #[DataProvider('guides')]
    public function testEachSettingNamedExists(string $guide): void
    {
        $settings = [];
        foreach ((new ReflectionClass(Settings::class))->getConstructor()?->getParameters() ?? [] as $parameter) {
            $settings[] = Settings::variableName($parameter->getName());
        }
        preg_match_all('/\bCLAVIA_[A-Z0-9_]+\b/', self::text($guide), $named);

        foreach (array_unique($named[0]) as $setting) {
            self::assertContains($setting, $settings, sprintf('%s.md names %s.', $guide, $setting));
        }
    }

    #[DataProvider('guides')]
    public function testNoRealHostIsNamed(string $guide): void
    {
        preg_match_all('#https?://([^/\s"\'`)<>]+)#', self::text($guide), $hosts);

        foreach (array_unique($hosts[1]) as $host) {
            self::assertMatchesRegularExpression(self::ALLOWED_HOSTS, $host, $guide . '.md');
        }
    }

    #[DataProvider('guides')]
    public function testLinksToOtherGuidesLandOnOne(string $guide): void
    {
        preg_match_all('#\]\(([a-z0-9-]+)\.md(?:\#([a-z0-9-]+))?\)#', self::text($guide), $links, PREG_SET_ORDER);

        foreach ($links as $link) {
            self::assertFileExists(self::GUIDES . '/' . $link[1] . '.md', $guide . '.md');
            if (isset($link[2])) {
                self::assertContains($link[2], self::anchors($link[1]), $guide . '.md links a missing heading.');
            }
        }
    }

    public function testThePageRendersThroughPinnedLibrariesAndSanitises(): void
    {
        $page = (string) file_get_contents(self::PAGE);
        preg_match_all('/<script[^>]*\bsrc="([^"]+)"/', $page, $scripts);

        self::assertSame([
            'https://cdn.jsdelivr.net/npm/marked@15.0.12/lib/marked.umd.js',
            'https://cdn.jsdelivr.net/npm/dompurify@3.2.6/dist/purify.min.js',
        ], $scripts[1]);
        self::assertStringContainsString('DOMPurify.sanitize(', $page, 'Never the Markdown\'s HTML as it is.');
        foreach (['{{RELEASE}}', '{{ROOT}}', '{{SLUG}}', '{{TITLE}}', '{{NAV}}'] as $placeholder) {
            self::assertStringContainsString($placeholder, $page);
        }
    }

    public function testTheThemeSwitchSharesTheReferencesChoice(): void
    {
        $page = (string) file_get_contents(self::PAGE);

        self::assertStringContainsString('id="clavia-theme"', $page);
        self::assertStringContainsString(
            "localStorage.getItem('colorMode')",
            $page,
            'Scalar keeps its theme under colorMode: the guides read the same key, so both pages agree.',
        );
        self::assertStringContainsString("localStorage.setItem('colorMode', next)", $page);
        self::assertStringContainsString(':root[data-theme="dark"]', $page);
        self::assertStringContainsString(':root:not([data-theme="light"])', $page);
    }

    /** @return iterable<string, array{string}> */
    public static function guides(): iterable
    {
        yield 'README' => ['README'];
        foreach (array_keys(self::listed()) as $guide) {
            yield $guide => [$guide];
        }
    }

    /** @return array<string, string> Each guide README.md lists, by file name, with its title. */
    private static function listed(): array
    {
        preg_match_all('/^\d+\. \[([^\]]+)\]\(([a-z0-9-]+)\.md\)/m', self::text('README'), $items, PREG_SET_ORDER);
        $listed = [];
        foreach ($items as $item) {
            $listed[$item[2]] = $item[1];
        }

        return $listed;
    }

    /** @return list<string> The anchors of a guide's headings, as GitHub and the page make them. */
    private static function anchors(string $guide): array
    {
        preg_match_all('/^#{2,3} (.+)$/m', self::text($guide), $headings);

        return array_map(
            static fn (string $heading): string => str_replace(' ', '-', (string) preg_replace(
                '/[^\p{L}\p{N}\s-]/u',
                '',
                mb_strtolower(trim($heading)),
            )),
            $headings[1],
        );
    }

    /** @return array<string, array<string, mixed>> A document's paths. */
    private static function paths(string $document): array
    {
        $parsed = Yaml::parseFile($document);
        self::assertIsArray($parsed);
        /** @var array<string, array<string, mixed>> */
        return $parsed['paths'];
    }

    private static function text(string $guide): string
    {
        $text = file_get_contents(self::GUIDES . '/' . $guide . '.md');
        self::assertIsString($text);

        return $text;
    }
}
