<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Primary\Http\Shared\Emphasise;
use Clavia\Adapter\Primary\Http\Shared\PageLanguage;
use Clavia\Application\Port\Messages;
use Psr\Container\ContainerInterface;

/** The templates' `emphasised()`, sharing the page's language with `t()` ({@see TranslateFactory}). */
final class EmphasiseFactory
{
    public function __invoke(ContainerInterface $container): Emphasise
    {
        /** @var Messages $messages */
        $messages = $container->get(Messages::class);
        /** @var PageLanguage $language */
        $language = $container->get(PageLanguage::class);

        return new Emphasise($messages, $language);
    }
}
