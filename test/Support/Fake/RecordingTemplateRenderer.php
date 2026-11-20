<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Mezzio\Template\TemplateRendererInterface;

/**
 * A template renderer that renders nothing and remembers what it was asked to render,
 * for unit tests of code that decides *which* page to show. What the page looks like is
 * the acceptance tests' business, through the real renderer.
 */
final class RecordingTemplateRenderer implements TemplateRendererInterface
{
    /** @var list<array{name: string, params: array<array-key, mixed>|object}> */
    public array $rendered = [];

    #[\Override]
    public function render(string $name, array|object $params = []): string
    {
        $this->rendered[] = ['name' => $name, 'params' => $params];

        return '<rendered ' . $name . '>';
    }

    #[\Override]
    public function addDefaultParam(string $templateName, string $param, mixed $value): void
    {
    }
}
