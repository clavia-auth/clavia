<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Shared\PageLanguage;
use Clavia\Adapter\Primary\Http\Shared\Translate;
use Clavia\Application\Port\Messages;
use Psr\Container\ContainerInterface;

/**
 * The templates' `t()`. laminas-view builds its helpers from its own plugin manager, whose creation context
 * is the application's container, so the helper and {@see PageRendererFactory} share one {@see PageLanguage}.
 */
final class TranslateFactory
{
    public function __invoke(ContainerInterface $container): Translate
    {
        /** @var Messages $messages */
        $messages = $container->get(Messages::class);
        /** @var PageLanguage $language */
        $language = $container->get(PageLanguage::class);

        return new Translate($messages, $language);
    }
}
