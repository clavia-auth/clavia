<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Secondary\Mail\NoMailer;
use Clavia\Adapter\Secondary\Mail\RenderedMailer;
use Clavia\Adapter\Secondary\Messages\IcuMessages;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Application\Port\RenderedMail;
use Clavia\Bootstrap\LanguageCatalogues;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use Psr\Log\NullLogger;

/**
 * A mail as the shipped catalogues word it, for tests of the use cases that compose mail: the
 * application holds no words, so what a mail says is read through the real {@see RenderedMailer}.
 */
final class TestMail
{
    private function __construct()
    {
    }

    /** English and French, English the default: what the deployment offers by default. */
    public static function languages(): Languages
    {
        return Languages::of([Language::fromString('en'), Language::fromString('fr')], Language::fromString('en'));
    }

    public static function render(OutgoingMail $mail): RenderedMail
    {
        $messages = new IcuMessages(LanguageCatalogues::DIRECTORY, self::languages(), new NullLogger());

        return new RenderedMailer(new NoMailer(), $messages)->render($mail);
    }
}
