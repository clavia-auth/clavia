<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\Messages\IcuMessages;
use Clavia\Bootstrap\LanguageCatalogues;
use Clavia\Domain\Shared\Languages;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;

/** The catalogue: the ARB files shipped in `translations/`, for the offered languages. */
final class IcuMessagesFactory
{
    public function __invoke(ContainerInterface $container): IcuMessages
    {
        /** @var Languages $languages */
        $languages = $container->get(Languages::class);
        /** @var LoggerInterface $logger */
        $logger = $container->get(LoggerInterface::class);

        return new IcuMessages(LanguageCatalogues::DIRECTORY, $languages, $logger);
    }
}
